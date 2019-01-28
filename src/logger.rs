extern crate log;

use log::{Record, Level, LevelFilter, Metadata, SetLoggerError};

static MY_LOGGER: SimpleLogger = SimpleLogger;
struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        // if self.enabled(record.metadata()) {
        //     println!("{} - {}", record.level(), record.args());
        // }
        let file = record.file().unwrap_or("<unknown file>");
        let line = record.line().unwrap_or(0);
        match record.level() {
            Level::Trace => SCLogMessage!(10,format!("{}",record.args()).as_str(),file,line),
            Level::Debug => SCLogMessage!(10,format!("{}",record.args()).as_str(),file,line),
            Level::Info  => SCLogMessage!(7, format!("{}",record.args()).as_str(),file,line),
            Level::Warn  => SCLogMessage!(5, format!("{}",record.args()).as_str(),file,line),
            Level::Error => SCLogMessage!(4, format!("{}",record.args()).as_str(),file,line),
        }
    }

    fn flush(&self) {
    }
}

pub fn init(max_level: LevelFilter) -> Result<(), SetLoggerError> {
    log::set_logger(&MY_LOGGER).map(|_| {
        log::set_max_level(max_level);
    })
}
