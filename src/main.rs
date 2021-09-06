use std::time::Duration;
use std::net::{ToSocketAddrs, TcpStream, Shutdown, UdpSocket};
use std::{thread, io};

mod pool;

use tokio::macros;
use tokio;
use rand::random;
use ipnet::Ipv4Net;
use std::str::FromStr;

#[tokio::main]
async fn main() {

    // let socket = UdpSocket::bind("127.0.0.1:8000")?;
    // match socket.connect("127.0.0.1:22"){
    //     Ok(x)=>{
    //         println!("正常连接{:?}",x);
    //     },
    //     Err(e)=>{
    //         println!("连接错误");
    //     }
    // };
    // let mut input = String::from("2121");
    // match socket.send(input.as_bytes()){
    //     Ok(x)=>{
    //         println!("正常1{:?}",x);
    //     },
    //     Err(e)=>{
    //         println!("发送失败端口没有打开1");
    //     }
    // };
    // let mut buffer = [0u8; 1500];
    // match socket.recv_from(&mut buffer){
    //         Ok(x)=>{
    //             println!("端口打开{:?}",x);
    //         },
    //         Err(e)=>{
    //             println!("接收错误");
    //         }
    // }
    // Ok(())
    //ip 存活扫描
    //udp 扫描
    // let socket = UdpSocket::bind("127.0.0.1:34254").unwrap();
    // socket.connect("127.0.0.1:8080").unwrap();
    // socket.send(&[0, 1, 2]).expect("couldn't send message");
    // match  socket.take_error() {
    //     Ok(x)=>{
    //         println!("正常{:?}",x);
    //     },
    //     _=>{
    //         println!("错误");
    //     }
    // }
    // let mut buf = [0; 10];
    //   match socket.peek(&mut buf) {
    //       Ok(received) => println!("received {} bytes", received),
    //       Err(e) => println!("peek function failed: {:?}", e),
    //   }
    // tcp 扫描


    // let th_pool: pool::ThreadPool = pool::ThreadPool::new(1000);
    // let timeout = Duration::from_millis(2000);
    //
    // ///扫描所有
    // /// 0-1023为系统保留端口
    // /// 1023 为
    // for i in 0..65535{
    //     let ic = i.clone();
    //     th_pool.execute( move ||{
    //         let value  = tcp_is_open("220.181.38.148".parse().unwrap(), ic, timeout);
    //         println!("端口{}扫描结果 {} ",ic,value);
    //     });
    // }
    // Ok(())



    let d =  gen_range_ip("192.168.1.1","192.168.1.255");
    let addr = "220.181.38.148".parse().unwrap();
    let timeout = Duration::from_secs(1);
    match ping::ping(addr, Some(timeout), Some(166), Some(3), Some(5), Some(&random())) {
        Ok(d) => {
            println!("成功")
        }
        Err(e) => {
            println!("错误")
        }
    };

    println!("端口22222")
}

fn tcp_is_open(hostname: String, port: u16, timeout: Duration) -> bool {
    let server = format!("{}:{}", hostname, port);
    let addrs: Vec<_> = server.to_socket_addrs().expect("Unable to parse socket address").collect();
    if let Ok(stream) = TcpStream::connect_timeout(&addrs[0], timeout) {
        stream.shutdown(Shutdown::Both).expect("shutdown call failed");
        true
    } else {
        false
    }
}


///只支持生成 ipv4
fn gen_range_ip(start: &str ,end:&str) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    results.push(start.clone().to_string());
    let startsSplit = start.split(".");
    let mut starts:Vec<u32> = Vec::new();
    for  d in startsSplit {
        let mut n: u32 = FromStr::from_str(d).unwrap();
        starts.push(n);
    }

    loop {
        let mut i = 4;
        let mut addvalue = false;
        while i > 0 {
            if  starts[i-1] < 255 {
                starts[i-1]+=1;
                addvalue = true;
                break;
            }
            i -= 1;
        }
        if !addvalue {
            ///无法在生成 IP
            break;
        }
        let mut ip = "".to_string();
        for x in &starts {
            ip+= &*(x.to_string() + ".");
        }
        ip.remove(ip.len()-1);
        results.push(ip.clone());
        if ip.eq(end) {
            break;
        }
    }
    results
}


fn udp_is_open(hostname: String, port: u16, timeout: Duration) -> bool {
    let server = format!("{}:{}", hostname, port);
    //let udp =  UdpSocket::connect(server).unwrap();
    println!("连接成功了");
    false
    // if let Ok(stream) = UdpSocket::connect_timeout(&addrs[0], timeout) {
    //     stream.shutdown(Shutdown::Both).expect("shutdown call failed");
    //     true
    // } else {
    //     false
    // }
}