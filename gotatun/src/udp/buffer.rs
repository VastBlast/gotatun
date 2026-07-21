// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//   Copyright (c) Mullvad VPN AB. All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

//! Generic buffered `UdpTransport` implementation.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures::{FutureExt, select};
use tokio::{io, sync::mpsc, time::sleep};

use crate::packet::{Packet, PacketBufPool};
use crate::task::Task;
use crate::udp::{UdpRecv, UdpSend};

const UDP_RECV_INITIAL_BACKOFF: Duration = Duration::from_millis(10);
const UDP_RECV_MAX_BACKOFF: Duration = Duration::from_secs(1);

fn is_recoverable_receive_error(kind: io::ErrorKind) -> bool {
    matches!(
        kind,
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
    )
}

/// A [`UdpSend`] that wraps another [`UdpSend`] to provide buffering.
///
/// Packets sent on this [`UdpSend::send_to`] will be buffered on a channel, and asynchronously
/// processed on another task. This means [`UdpSend::send_to`] won't block unless the channel is
/// full.
#[derive(Clone)]
pub struct BufferedUdpSend {
    _send_task: Arc<Task>,

    /// Channel where IPv4 packets are sent to `_send_task`
    send_tx_v4: mpsc::Sender<(Packet, SocketAddr)>,

    /// Channel where IPv6 packets are sent to `_send_task`
    send_tx_v6: mpsc::Sender<(Packet, SocketAddr)>,
}

impl BufferedUdpSend {
    /// Wrap a [`UdpSend`] into a [`BufferedUdpSend`] with `capacity`.
    pub fn new(capacity: usize, udp_tx: impl UdpSend + 'static) -> Self {
        let (send_tx_v4, mut send_rx_v4) = mpsc::channel::<(Packet, SocketAddr)>(capacity);
        let (send_tx_v6, mut send_rx_v6) = mpsc::channel::<(Packet, SocketAddr)>(capacity);

        let send_task = Task::spawn("buffered UDP send", async move {
            let mut buf_v4 = vec![];
            let mut buf_v6 = vec![];
            let max_packet_count = udp_tx.max_number_of_packets_to_send();
            let mut send_many_buf = Default::default();

            loop {
                // use seperate channels because we musn't call `send_many_to` with mixed IPv4/IPv6.
                let (count, buf) = select! {
                    // recv_many is cancel-safe
                    n = send_rx_v4.recv_many(&mut buf_v4, max_packet_count).fuse() => (n, &mut buf_v4),
                    n = send_rx_v6.recv_many(&mut buf_v6, max_packet_count).fuse() => (n, &mut buf_v6),
                };
                match count {
                    0 => break,
                    1 => {
                        let (packet, addr) =
                            buf.pop().expect("recv_many received 1 packet into buf");
                        let _ = udp_tx
                            .send_to(packet, addr)
                            .await
                            .inspect_err(|e| tracing::trace!("send_to_err: {e:#}"));
                    }
                    2.. => {
                        // send all packets at once
                        if let Err(e) = udp_tx.send_many_to(&mut send_many_buf, buf).await {
                            tracing::trace!("send_to_many_err: {e:#}");
                            if !buf.is_empty() {
                                tracing::trace!(
                                    "send_to_many dropping {} packets due to error.",
                                    buf.len()
                                );
                                buf.clear(); // give up, drop the packets we meant to send
                            }
                        }
                    }
                }
            }
        });

        Self {
            _send_task: Arc::new(send_task),
            send_tx_v4,
            send_tx_v6,
        }
    }
}

impl UdpSend for BufferedUdpSend {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        let tx = match destination {
            SocketAddr::V4(..) => &self.send_tx_v4,
            SocketAddr::V6(..) => &self.send_tx_v6,
        };
        tx.send((packet, destination))
            .await
            .expect("receiver task is never stopped while Self exists");
        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        debug_assert_eq!(
            self.send_tx_v4.max_capacity(),
            self.send_tx_v6.max_capacity(),
        );
        self.send_tx_v4.max_capacity()
    }
}

/// A [`UdpRecv`] that wraps another [`UdpRecv`] to provide buffering.
///
/// This will spawn a background task that continuously calls [`UdpRecv::recv_many_from`] until the
/// buffer is full. Any call to [`UdpRecv::recv_from`] on _this_ object will not block unless the
/// buffer is empty. Recoverable receive errors are retried; terminal errors are returned after any
/// already-buffered packets.
pub struct BufferedUdpReceive {
    _recv_task: Arc<Task>,
    recv_rx: mpsc::Receiver<io::Result<(Packet, SocketAddr)>>,
}

impl BufferedUdpReceive {
    /// Wrap a [`UdpRecv`] into a [`BufferedUdpReceive`] with `capacity`.
    pub fn new(
        capacity: usize,
        mut udp_rx: impl UdpRecv + 'static,
        mut recv_pool: PacketBufPool,
    ) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel(capacity);

        let recv_task = Task::spawn("buffered UDP receive", async move {
            let mut recv_many_buf = Default::default();
            let mut packet_bufs = vec![];
            let mut retry_delay = UDP_RECV_INITIAL_BACKOFF;

            loop {
                // Read packets from the socket.
                if let Err(error) = udp_rx
                    .recv_many_from(&mut recv_many_buf, &mut recv_pool, &mut packet_bufs)
                    .await
                {
                    packet_bufs.clear();

                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    if is_recoverable_receive_error(error.kind()) {
                        tracing::trace!(
                            "UDP receive failed: {error:#}; retrying in {retry_delay:?}"
                        );
                        sleep(retry_delay).await;
                        retry_delay = retry_delay.saturating_mul(2).min(UDP_RECV_MAX_BACKOFF);
                        continue;
                    }

                    let _ = recv_tx.send(Err(error)).await;
                    return;
                }

                retry_delay = UDP_RECV_INITIAL_BACKOFF;

                for (packet_buf, src) in packet_bufs.drain(..) {
                    match recv_tx.try_send(Ok((packet_buf, src))) {
                        Ok(()) => (),
                        Err(mpsc::error::TrySendError::Full(packet)) => {
                            if recv_tx.send(packet).await.is_err() {
                                // Buffer dropped
                                return;
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
        });

        Self {
            _recv_task: Arc::new(recv_task),
            recv_rx,
        }
    }
}

impl UdpRecv for BufferedUdpReceive {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, _pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        self.recv_rx.recv().await.unwrap_or_else(|| {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffered UDP receive task stopped",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::pending,
        io,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use tokio::{
        sync::mpsc,
        time::{Instant, timeout},
    };

    use super::*;

    const CALL_TIMEOUT: Duration = Duration::from_secs(30);
    const SOURCE: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1234));

    enum RecvOutcome {
        Success(Vec<(Packet, SocketAddr)>),
        Failure(Vec<(Packet, SocketAddr)>, io::Error),
        Pending,
    }

    struct ScriptedUdpRecv {
        outcomes: VecDeque<RecvOutcome>,
        calls: mpsc::UnboundedSender<Instant>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for ScriptedUdpRecv {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl UdpRecv for ScriptedUdpRecv {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            _pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            unreachable!("BufferedUdpReceive uses recv_many_from")
        }

        async fn recv_many_from(
            &mut self,
            _recv_buf: &mut Self::RecvManyBuf,
            _pool: &mut PacketBufPool,
            packets: &mut Vec<(Packet, SocketAddr)>,
        ) -> io::Result<()> {
            self.calls.send(Instant::now()).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "test controller was dropped")
            })?;

            match self.outcomes.pop_front().unwrap_or(RecvOutcome::Pending) {
                RecvOutcome::Success(received) => {
                    packets.extend(received);
                    Ok(())
                }
                RecvOutcome::Failure(received, error) => {
                    packets.extend(received);
                    Err(error)
                }
                RecvOutcome::Pending => pending().await,
            }
        }
    }

    struct Harness {
        receiver: BufferedUdpReceive,
        calls: mpsc::UnboundedReceiver<Instant>,
        udp_dropped: Arc<AtomicBool>,
    }

    impl Harness {
        fn new(capacity: usize, outcomes: impl IntoIterator<Item = RecvOutcome>) -> Self {
            let (calls_tx, calls) = mpsc::unbounded_channel();
            let udp_dropped = Arc::new(AtomicBool::new(false));
            let udp_rx = ScriptedUdpRecv {
                outcomes: outcomes.into_iter().collect(),
                calls: calls_tx,
                dropped: Arc::clone(&udp_dropped),
            };

            Self {
                receiver: BufferedUdpReceive::new(capacity, udp_rx, PacketBufPool::new(capacity)),
                calls,
                udp_dropped,
            }
        }

        async fn next_call(&mut self) -> Instant {
            timeout(CALL_TIMEOUT, self.calls.recv())
                .await
                .expect("timed out waiting for recv_many_from")
                .expect("UDP receiver stopped unexpectedly")
        }

        async fn receive(&mut self) -> io::Result<(Packet, SocketAddr)> {
            timeout(
                CALL_TIMEOUT,
                self.receiver.recv_from(&mut PacketBufPool::new(0)),
            )
            .await
            .expect("timed out waiting for buffered packet")
        }
    }

    fn packet(contents: &[u8]) -> (Packet, SocketAddr) {
        (Packet::copy_from(contents), SOURCE)
    }

    fn success(contents: &[u8]) -> RecvOutcome {
        RecvOutcome::Success(vec![packet(contents)])
    }

    fn failure(kind: io::ErrorKind) -> RecvOutcome {
        RecvOutcome::Failure(vec![], io::Error::from(kind))
    }

    #[test]
    fn classifies_receive_errors() {
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkDown,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::TimedOut,
            io::ErrorKind::WouldBlock,
        ] {
            assert!(is_recoverable_receive_error(kind));
        }

        for kind in [
            io::ErrorKind::AddrNotAvailable,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::Interrupted,
            io::ErrorKind::InvalidData,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::NotConnected,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::Unsupported,
        ] {
            assert!(!is_recoverable_receive_error(kind));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn starts_and_receives_without_backoff() {
        let started_at = Instant::now();
        let mut harness = Harness::new(1, [success(b"packet"), RecvOutcome::Pending]);

        assert_eq!(harness.next_call().await, started_at);
        assert_eq!(harness.receive().await.unwrap().0.as_ref(), b"packet");
        assert_eq!(Instant::now(), started_at);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_interrupted_immediately() {
        let mut harness = Harness::new(
            1,
            [
                failure(io::ErrorKind::Interrupted),
                success(b"packet"),
                RecvOutcome::Pending,
            ],
        );

        let first_call = harness.next_call().await;
        let retry = harness.next_call().await;

        assert_eq!(retry, first_call);
        assert_eq!(harness.receive().await.unwrap().0.as_ref(), b"packet");
    }

    #[tokio::test(start_paused = true)]
    async fn backs_off_caps_and_resets_after_success() {
        const ERROR_COUNT: usize = 10;

        let mut outcomes = (0..ERROR_COUNT)
            .map(|_| failure(io::ErrorKind::NetworkDown))
            .collect::<Vec<_>>();
        outcomes.extend([
            success(b"success"),
            failure(io::ErrorKind::NetworkDown),
            RecvOutcome::Pending,
        ]);
        let mut harness = Harness::new(1, outcomes);
        let mut calls = Vec::with_capacity(ERROR_COUNT + 3);
        for _ in 0..ERROR_COUNT + 3 {
            calls.push(harness.next_call().await);
        }

        let mut expected_delay = UDP_RECV_INITIAL_BACKOFF;
        for pair in calls[..=ERROR_COUNT].windows(2) {
            assert_eq!(pair[1] - pair[0], expected_delay);
            expected_delay = expected_delay.saturating_mul(2).min(UDP_RECV_MAX_BACKOFF);
        }
        assert_eq!(expected_delay, UDP_RECV_MAX_BACKOFF);

        assert_eq!(calls[ERROR_COUNT + 1], calls[ERROR_COUNT]);
        assert_eq!(
            calls[ERROR_COUNT + 2] - calls[ERROR_COUNT + 1],
            UDP_RECV_INITIAL_BACKOFF
        );
        assert_eq!(harness.receive().await.unwrap().0.as_ref(), b"success");
    }

    #[tokio::test(start_paused = true)]
    async fn clears_partial_batch_before_retry() {
        let mut harness = Harness::new(
            1,
            [
                RecvOutcome::Failure(
                    vec![packet(b"stale")],
                    io::Error::from(io::ErrorKind::NetworkDown),
                ),
                success(b"fresh"),
                RecvOutcome::Pending,
            ],
        );

        assert_eq!(harness.receive().await.unwrap().0.as_ref(), b"fresh");
    }

    #[tokio::test(start_paused = true)]
    async fn preserves_terminal_receive_error() {
        let mut harness = Harness::new(
            1,
            [RecvOutcome::Failure(
                vec![],
                io::Error::new(io::ErrorKind::InvalidData, "terminal receive failure"),
            )],
        );

        let error = harness.receive().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "terminal receive failure");
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_receiver_cancels_backoff() {
        let mut harness = Harness::new(
            1,
            [failure(io::ErrorKind::NetworkDown), RecvOutcome::Pending],
        );
        let error_at = harness.next_call().await;

        for _ in 0..4 {
            tokio::task::yield_now().await;
            assert_eq!(Instant::now(), error_at);
            assert!(matches!(
                harness.calls.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }

        drop(harness.receiver);
        for _ in 0..32 {
            if harness.udp_dropped.load(Ordering::SeqCst) {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("underlying UDP receiver was not dropped after cancellation");
    }
}
