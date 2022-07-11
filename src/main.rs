use std::time::{Duration, Instant};
use std::net::{ToSocketAddrs, TcpStream, Shutdown};
use std::io;
// mod pool;
use tokio;
use std::str::FromStr;
use std::io::Write;
use surge_ping::IcmpPacket;
use lazy_static::lazy_static;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::fs::File;

lazy_static! {
  static ref  RESULTS:Mutex<HashMap<String,String>> = Mutex::new(HashMap::new());
    static ref PORTS:std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(vec![]);
}

use clap::{Arg, App};
use std::sync::Arc;
use local_ip_address::local_ip;
use async_recursion::async_recursion;
use rlimit::Resource;



// #[tokio::main(flavor = "multi_thread", worker_threads = 1000)]
// #[tokio::main]
fn main()  {
    let matches = App::new("TCP port scanner Program")
        .version("0.1.3")
        .author("janiokq <janiokq@gmail.com>")
        .about("This is TCP port scanner written using RUST")
        .arg(Arg::with_name("outfile")
            .short('o')
            .long("outfile")
            .takes_value(true)
            .help("Result Output file path"))
        .arg(Arg::with_name("ips")
            .short('i')
            .long("ipRange")
            .takes_value(true)
            .help("This is the IP range parameter\n\
            ip,ip   Multiple IP description\n\
            or
            ip-ip   Description of a range of IP
            "))
        .arg(Arg::with_name("port")
            .short('p')
            .long("port")
            .takes_value(true)
            .help("This is the Port range parameter\n\
            port,port   Multiple Port description\n\
            or\n\
            port-port   Description of a range of Port
            "))
        .arg(Arg::with_name("thread")
            .short('t')
            .long("threads")
            .takes_value(true)
            .help("Use the number of worker threads。  The default value is the current number of physical cores x 2 "))
        .get_matches();

    match Resource::NOFILE.get() {
        Ok(d)=>{
            Resource::FSIZE.set(d.1, d.1).unwrap();
        },
        Err(_e)=>{
        }
    }
    // try
    let ips = matches.value_of("ips");
    let ports = matches.value_of("port");
    let mut ip_range: Vec<String> = Vec::new();
    match ips {
        None => {
            let my_local_ip = local_ip().unwrap();
            let mut start_ip: Vec<String> = Vec::new();
            for x in my_local_ip.to_string().split(".") {
                start_ip.push(x.to_string());
            }
            let slen = start_ip.len();
            start_ip[slen - 1] = "1".to_string();
            let mut end_ip: Vec<String> = start_ip.clone();
            let elen = end_ip.len();
            end_ip[elen - 1] = "255".to_string();

            let mut sip = "".to_string();
            for x in start_ip {
                sip += &*(x + ".");
            }
            sip.remove(sip.len() - 1);

            let mut eip = "".to_string();
            for x in end_ip {
                eip += &*(x + ".");
            }
            eip.remove(eip.len() - 1);
            ip_range = gen_range_ip(&sip, &eip)
        }
        Some(s) => {
            match s.find(",") {
                None => {
                    match s.find("-") {
                        None => {
                            ip_range.push(s.to_string());
                        }
                        Some(_index) => {
                            let mut start = "";
                            let mut end = "";
                            for x in s.split("-") {
                                if start.eq("") {
                                    start = x;
                                } else {
                                    end = x;
                                }
                            }
                            ip_range = gen_range_ip(start, end)
                        }
                    }
                }
                Some(_index) => {
                    for x in s.split(",") {
                        if !x.eq(",") {
                            ip_range.push(x.to_string());
                        }
                    }
                }
            }
        }
    }
    match ports {
        None => {
            // Default full port
            let mut start: u16 = 0;
            let end: u16 = 65535;
            while start < end {
                start += 1;
                PORTS.lock().unwrap().push(start);
            }
        }
        Some(s) => {
            match s.find(",") {
                None => {
                    match s.find("-") {
                        None => {
                            PORTS.lock().unwrap().push(s.parse::<u16>().unwrap());
                        }
                        Some(_index) => {
                            let mut start: u16 = 0;
                            let mut end: u16 = 0;
                            for x in s.split("-") {
                                if start == 0 {
                                    start = x.parse::<u16>().unwrap();
                                } else {
                                    end = x.parse::<u16>().unwrap();
                                }
                            }

                            while start < end {
                                PORTS.lock().unwrap().push(start);
                                start += 1;
                            }
                        }
                    }
                }
                Some(_index) => {
                    for x in s.split(",") {
                        if !x.eq(",") {
                            PORTS.lock().unwrap().push(x.parse::<u16>().unwrap());
                        }
                    }
                }
            }
        }
    }
    let now = Instant::now();
    let mut threads  = num_cpus::get();
    match  matches.value_of("thread") {
        Some(t)=>{
            match t.parse::<usize>() {
                Ok(thr)=>{
                    if thr != 0 {
                        threads = thr;
                    }
                },
                Err(_e)=>{
                }
            }
        },
        None=>{}
    } ;




    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {

            println!("total IP addresses {}", ip_range.len());

            _ = scan(0,ip_range).await;
            // sleep(Duration::from_millis(10000)).await;

            println!("total time consuming ：{} ms", now.elapsed().as_millis());
            println!("scan end ....");

            let global_results = RESULTS.lock().await;
            println!("{:?}", global_results);
            let outfile = matches.value_of("outfile").unwrap_or("./scan_results.txt");

            let mut file = File::create(outfile).unwrap();
            for item in global_results.iter() {
                file.write(item.0.as_ref()).unwrap();
                file.write(b":").unwrap();
                file.write(item.1.as_ref()).unwrap();
                file.write(b"\n").unwrap();
            }
            println!("写入完成");
        });
}

#[async_recursion]
#[inline]
async fn scan(start_p:usize,ip_range: Vec<String>) -> io::Result<()> {
    let mut handles = Vec::new();
    let mut start_position: usize = start_p;
    let mut has_error = false;
    while start_position < ip_range.len()  {
        let addr:String = ip_range[start_position].parse().unwrap();
            match surge_ping::ping(addr.parse().unwrap(), &[1,]).await {
                Ok((IcmpPacket::V4(_), _)) => {
                    handles.push(tokio::spawn(async move {
                      _ =  port_scanning(addr.to_string()).await;
                    }));
                },
                Ok(_) => {
                    has_error = true;
                },
                Err(e) => {
                    has_error = true;
                    println!("{:?}", e)
                },
            };
        start_position+=1;
    };

    for handle in handles {
        handle.await?;
    }
    if has_error {
       _ = scan(start_position.clone(),ip_range.clone()).await;
    }

    Ok(())
}

// async fn ping_ip(addr: String, pinger: Pinger) -> io::Result<()> {
//     match pinger.ping(0).await {
//         Ok(reply) => {
//             port_scanning(addr.to_string()).await;

//             Ok(())
//         }
//         Err(e) => {
//             // println!("Unable to access IP {}", addr);
//             Ok(())
//         }
//     }
// }

#[inline]
async fn port_scanning(addr: String) -> io::Result<()> {
    let timeout = Duration::from_millis(500);
    let open_port = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    let now = Instant::now();
    let data1 = Arc::new(Mutex::new(0));
    let addr2 = addr.clone();

    for i in PORTS.lock().unwrap().iter() {
        let ic = i.clone();
        let ad = addr.clone();
        let my_port = Arc::clone(&open_port);
        let data2 = Arc::clone(&data1);
        handles.push(tokio::spawn(async move {
            let value = tcp_is_open(ad.parse().unwrap(), ic, timeout);
            if value {
                let mut lock = my_port.lock().await;
                lock.push(ic);
            }
            let mut lock = data2.lock().await;
            *lock += 1;
        }));
    }
    for handle in handles {
        handle.await?;
    }
    let results = open_port.lock().await;
    if results.len() > 0 {
        let mut global_results = RESULTS.lock().await;
        let mut ports = "".to_string();
        for i in results.to_vec() {
            ports += &*(i.to_string() + ",");
        }
        global_results.insert(addr, ports);
    }
    let lock = data1.lock().await;
    println!("{} completes task {}：consuming {} ms", lock, addr2, now.elapsed().as_millis());


    Ok(())
}

#[inline]
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
fn gen_range_ip(start: &str, end: &str) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    results.push(start.clone().to_string());
    let starts_split = start.split(".");
    let mut starts: Vec<u32> = Vec::new();
    for d in starts_split {
        let n: u32 = FromStr::from_str(d).unwrap();
        starts.push(n);
    }

    loop {
        let mut i = 4;
        let mut addvalue = false;
        while i > 0 {
            if starts[i - 1] < 256 {
                starts[i - 1] += 1;
                if starts[i - 1] == 256 {
                    let cleari = i - 2;
                    if cleari > 0 {
                        starts[cleari] += 1;
                        starts[i - 1] = 1;
                    }
                }
                addvalue = true;
                break;
            }
            i -= 1;
        }
        if !addvalue {
            // 无法在生成 IP
            break;
        }
        let mut ip = "".to_string();
        for x in &starts {
            ip += &*(x.to_string() + ".");
        }
        ip.remove(ip.len() - 1);
        results.push(ip.clone());
        if ip.eq(end) {
            break;
        }
    }
    results
}


// fn udp_is_open(hostname: String, port: u16, timeout: Duration) -> bool {
//     let server = format!("{}:{}", hostname, port);
//     //let udp =  UdpSocket::connect(server).unwrap();
//     println!("连接成功了");
//     false
//     // if let Ok(stream) = UdpSocket::connect_timeout(&addrs[0], timeout) {
//     //     stream.shutdown(Shutdown::Both).expect("shutdown call failed");
//     //     true
//     // } else {
//     //     false
//     // }
// }