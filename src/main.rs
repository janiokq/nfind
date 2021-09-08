use std::time::{Duration, Instant};
use std::net::{ToSocketAddrs, TcpStream, Shutdown, UdpSocket};
use std::{thread, io};

mod pool;

use tokio::{macros, runtime};
use tokio;
use rand::random;
use ipnet::Ipv4Net;
use std::str::FromStr;
use surge_ping::Pinger;
use std::io::{Error, Write};
use std::future::Future;
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
use tokio::runtime::{Builder, Runtime};
use tokio::time::sleep;
use local_ip_address::local_ip;

#[tokio::main]
async fn main() -> io::Result<()> {




    let matches = App::new("TCP port scanner Program")
        .version("0.1.0")
        .author("janiokq <janiokq@gmail.com>")
        .about("This is TCP port scanner written using RUST")
        .arg(Arg::with_name("outfile")
            .short("outf")
            .long("outfile")
            .takes_value(true)
            .help("Result Output file path"))
        .arg(Arg::with_name("ips")
            .short("ip")
            .long("ipRange")
            .takes_value(true)
            .help("This is the IP range parameter\n\
            ip,ip   Multiple IP description\n\
            or
            ip-ip   Description of a range of IP
            "))
        .arg(Arg::with_name("port")
            .short("p")
            .long("port")
            .takes_value(true)
            .help("This is the Port range parameter\n\
            port,port   Multiple Port description\n\
            or\n\
            port-port   Description of a range of Port
            "))
        .get_matches();

    let ips = matches.value_of("ips");
    let ports = matches.value_of("port");
    let mut ip_range: Vec<String> = Vec::new();
    match ips {
        None => {

            let my_local_ip = local_ip().unwrap();
            let mut start_ip:Vec<String> = Vec::new();
            for x in my_local_ip.to_string().split(".") {
                start_ip.push(x.to_string());
            }
           let slen = start_ip.len();
            start_ip[slen-1] = "1".to_string();
            let mut end_ip:Vec<String> = start_ip.clone();
            let elen = end_ip.len();
            end_ip[elen-1] = "255".to_string();

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
            let model = false;
            match s.find(",") {
                None => {
                    match s.find("-") {
                        None => {
                            ip_range.push(s.to_string());
                        }
                        Some(index) => {
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
                Some(index) => {
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
            ///Default full port
            let mut start: u16 = 0;
            let mut end: u16 = 65535;
            while start < end {
                start+=1;
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
                        Some(index) => {
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
                                start+=1;
                            }

                        }
                    }
                }
                Some(index) => {
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
    let timeout_ping = Duration::from_millis(200);
    let mut handles = Vec::new();
    println!("total IP addresses {}",ip_range.len());

    let data1 = Arc::new(Mutex::new(0));
    for x in ip_range {
        let addr = x.parse().unwrap();
        let mut pinger = Pinger::new(addr).unwrap();
        pinger.timeout(timeout_ping);
        let data2 = Arc::clone(&data1);
        handles.push(tokio::spawn(async move {
            sleep(Duration::from_millis(1000)).await;
            ping_ip(addr.to_string(), pinger,).await;
            let mut lock = data2.lock().await;
            *lock += 1;
        }));
    }

    for handle in handles {
        handle.await?;
    }

    let mut lock = data1.lock().await;
    println!("total time consuming ：{} ms", now.elapsed().as_millis());
    println!("scan end ....");
    let mut global_results = RESULTS.lock().await;
    println!("{:?}",global_results);
    let outfile = matches.value_of("outfile").unwrap_or("./scan_results.txt");

    let mut file = File::create(outfile).unwrap();
    for item in global_results.iter() {
        file.write(item.0.as_ref()).unwrap();
        file.write(b":").unwrap();
        file.write(item.1.as_ref()).unwrap();
        file.write(b"\n").unwrap();
    }
    Ok(())
}

async fn ping_ip(addr: String, pinger: Pinger) -> io::Result<()> {
    match pinger.ping(0).await {
        Ok(reply) => {
            port_scanning(addr.to_string()).await;
            Ok(())
        }
        Err(e) => {
            // println!("Unable to access IP {}", addr);
            Ok(())
        }
    }
}

async fn port_scanning(addr: String) -> io::Result<()> {
    let timeout = Duration::from_millis(200);
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
    let mut results = open_port.lock().await;
    if results.len() > 0 {
        let mut global_results = RESULTS.lock().await;
        let mut ports = "".to_string();
        for i in results.to_vec() {
            ports += &*(i.to_string() + ",");
        }
        global_results.insert(addr, ports);
    }
    let mut lock = data1.lock().await;
    println!("{} completes task {}：consuming {} ms",lock,addr2, now.elapsed().as_millis());



    Ok(())
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
fn gen_range_ip(start: &str, end: &str) -> Vec<String> {
    let mut results: Vec<String> = Vec::new();
    results.push(start.clone().to_string());
    let starts_split = start.split(".");
    let mut starts: Vec<u32> = Vec::new();
    for d in starts_split {
        let mut n: u32 = FromStr::from_str(d).unwrap();
        starts.push(n);
    }

    loop {
        let mut i = 4;
        let mut addvalue = false;
        while i > 0 {
            if starts[i - 1] < 256 {
                starts[i - 1] += 1;
                if starts[i - 1] == 256 {
                    let mut cleari = i-2;
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
            ///无法在生成 IP
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