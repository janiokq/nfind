use std::thread;
use std::sync::{Arc,mpsc,Mutex};
pub struct ThreadPool{
    workers:Vec<Worker>,
    sender:mpsc::Sender<Message>,
}
impl ThreadPool {
    pub fn new(size:usize) ->ThreadPool {
        assert!(size>0);
        let mut workers = Vec::with_capacity(size);
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        for id in 0..size {
            workers.push(Worker::new(id,Arc::clone(&receiver )));
        }
        ThreadPool {
            workers,
            sender
        }
    }
    pub fn execute<F>(&self,f:F)
    where
        F:FnOnce() + Send + 'static
    {
        let job = Box::new(f);
        self.sender.send(Message::NewJob(job)).unwrap();
    }
}
impl Drop for ThreadPool {
    fn drop(&mut self){
        for _worker in &mut self.workers {
            self.sender.send(Message::Terminate).unwrap();
        }
        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}
type Job = Box<dyn FnOnce() + Send + 'static >;
struct Worker {
    id:usize,
    thread:Option<thread::JoinHandle<()>>,
}
impl Worker {
    fn new(id: usize,receiver: Arc<Mutex<mpsc::Receiver<Message>>> ) -> Worker {
        let thread  = thread::spawn( move || loop {
            let message  = receiver.lock().unwrap().recv().unwrap();
            match message {
                Message::NewJob(job) =>{
                    job();
                },
                Message::Terminate =>{
                    break;
                }
            }
        });
        Worker{id,thread:Some(thread)}
    }
}
enum  Message {
    NewJob(Job),
    Terminate
}
