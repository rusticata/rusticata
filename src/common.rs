use libc::c_void;

pub type LogCallback = extern "C" fn (lvl: u32, file: *const c_void, line: u32, func: *const c_void, err: u32, msg: *const c_void);
// 
// static RAW_LOG : *mut LogCallback = ||{};
// 
// #[macro_export]
// macro_rules! SCLogMessage (
//   ($lvl:expr, $msg:expr) => (
//     {
//         unsafe {  }
//     }
//   );
//   ($lvl:expr, $msg:expr) => (
//     SCLogMessage!($i, $cond, $err);
//   );
// );

#[repr(C)]
pub struct SuricataConfig {
    pub magic: u32,
    pub log: LogCallback,
    // other members
}

pub static mut suricata_config : Option<&'static SuricataConfig> = None;

pub fn raw_sclog_message<'a,'b>(lvl: u32, msg: &'a str, file: &'b str, line: u32) {
    match unsafe{suricata_config} {
        None => println!("({}:{}) [{}]: {}", file, line, lvl, msg),
        Some(c) => {
            let c_file = file.as_ptr() as *const c_void;
            let c_func = "<rust function>\0".as_ptr() as *const c_void;
            let c_ptr = msg.as_ptr() as *const c_void;

            (c.log)(lvl, c_file, line, c_func, 0, c_ptr);
        },
    };
}

#[macro_export]
macro_rules! SCLogMessage (
  ($lvl:expr, $msg:expr, $file:expr, $line:expr) => (
    {
        $crate::raw_sclog_message($lvl,$msg, $file, $line)
    }
  );
  ($lvl:expr, $msg:expr) => (
    SCLogMessage!($lvl, $msg, file!(), line!());
  );
);

#[macro_export]
macro_rules! SCLogAlert (
  ($msg:expr) => ( { SCLogMessage!(2,$msg); });
  ($msg:expr) => ( SCLogAlert!($msg););
);

#[macro_export]
macro_rules! SCLogError (
  ($msg:expr) => ( { SCLogMessage!(4,$msg); });
  ($msg:expr) => ( SCLogError!($msg););
);

#[macro_export]
macro_rules! SCLogWarning (
  ($msg:expr) => ( { SCLogMessage!(5,$msg); });
  ($msg:expr) => ( SCLogWarning!($msg););
);

#[macro_export]
macro_rules! SCLogNotice (
  ($msg:expr) => ( { SCLogMessage!(6,$msg); });
  ($msg:expr) => ( SCLogNotice!($msg););
);

#[macro_export]
macro_rules! SCLogInfo (
  ($msg:expr) => ( { SCLogMessage!(7,$msg); });
  ($msg:expr) => ( SCLogInfo!($msg););
);

#[macro_export]
macro_rules! SCLogDebug (
  ($msg:expr) => ( { SCLogMessage!(10,$msg); });
  ($msg:expr) => ( SCLogDebug!($msg););
);


