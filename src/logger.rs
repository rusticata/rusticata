extern crate log;

use log::{LogRecord, LogLevel, LogLevelFilter, LogMetadata, SetLoggerError};

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Debug
    }

    fn log(&self, record: &LogRecord) {
        // if self.enabled(record.metadata()) {
        //     println!("{} - {}", record.level(), record.args());
        // }
        match record.level() {
            LogLevel::Trace => SCLogDebug!(format!("{}",record.args()).as_str()),
            LogLevel::Debug => SCLogDebug!(format!("{}",record.args()).as_str()),
            LogLevel::Info => SCLogInfo!(format!("{}",record.args()).as_str()),
            LogLevel::Warn => SCLogWarning!(format!("{}",record.args()).as_str()),
            LogLevel::Error => SCLogError!(format!("{}",record.args()).as_str()),
        }
    }
}

pub fn init(max_level: LogLevelFilter) -> Result<(), SetLoggerError> {
    log::set_logger(|max_log_level| {
        max_log_level.set(max_level);
        Box::new(SimpleLogger)
    })
}
