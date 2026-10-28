use std::{collections::BTreeMap, time::Duration};

use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
    task::JoinHandle,
};

#[derive(Debug)]
pub struct Request {
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub delay: Duration,
}

impl Reply {
    pub fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

pub struct Server {
    pub url: String,
    pub requests: mpsc::UnboundedReceiver<Request>,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn serve(replies: Vec<Reply>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (sent, requests) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        for reply in replies {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let header_end = loop {
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "request closed before headers");
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break offset + 4;
                }
            };
            let head = std::str::from_utf8(&bytes[..header_end]).unwrap();
            let mut lines = head.split("\r\n");
            let target = lines
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .to_owned();
            let headers = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
                .collect::<BTreeMap<_, _>>();
            let length = headers
                .get("content-length")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            while bytes.len() < header_end + length {
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).await.unwrap();
                assert_ne!(read, 0, "request closed before body");
                bytes.extend_from_slice(&buffer[..read]);
            }
            let body = serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
            if sent
                .send(Request {
                    target,
                    headers,
                    body,
                })
                .is_err()
            {
                return;
            }
            tokio::time::sleep(reply.delay).await;
            let headers = reply
                .headers
                .into_iter()
                .map(|(name, value)| format!("{name}: {value}\r\n"))
                .collect::<String>();
            let response = format!(
                "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{}\r\n{}",
                reply.status,
                reply.body.len(),
                headers,
                reply.body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    Server {
        url,
        requests,
        task,
    }
}
