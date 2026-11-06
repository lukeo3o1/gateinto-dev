use std::error::Error;
use std::fmt;
use std::io;

#[cfg(windows)]
pub use windows::{Process, SpawnOptions};

pub struct Job {
    #[cfg(windows)]
    handle: crate::token::Handle,
}

impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Job").finish_non_exhaustive()
    }
}

impl Job {
    #[cfg(windows)]
    pub fn new() -> io::Result<Self> {
        windows::create().map(|handle| Self { handle })
    }

    #[cfg(not(windows))]
    pub fn new() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "job objects are only available on Windows",
        ))
    }

    #[cfg(all(test, not(windows)))]
    pub(crate) fn fake() -> Self {
        Self {}
    }

    #[cfg(windows)]
    pub(crate) fn handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.handle.0
    }
}

#[derive(Debug)]
pub enum SpawnError {
    Job(io::Error),
    Process(io::Error),
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Job(error) => write!(f, "putting the process in the job failed: {error}"),
            Self::Process(error) => error.fmt(f),
        }
    }
}

impl Error for SpawnError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Job(error) | Self::Process(error) => Some(error),
        }
    }
}

const QUOTE: u16 = b'"' as u16;
const BACKSLASH: u16 = b'\\' as u16;

#[cfg_attr(not(windows), allow(dead_code))]
fn command_line(executable: &[u16], args: &[Vec<u16>]) -> io::Result<Vec<u16>> {
    if executable.contains(&QUOTE) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the executable path contains a quote",
        ));
    }
    if executable.contains(&0) || args.iter().any(|arg| arg.contains(&0)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the command line contains a NUL character",
        ));
    }
    let mut line = vec![QUOTE];
    line.extend_from_slice(executable);
    line.push(QUOTE);
    for arg in args {
        line.push(u16::from(b' '));
        quote(arg, &mut line);
    }
    line.push(0);
    Ok(line)
}

fn quote(arg: &[u16], line: &mut Vec<u16>) {
    let plain = !arg.is_empty()
        && !arg
            .iter()
            .any(|&unit| matches!(unit, 0x20 | 0x09 | 0x0A | 0x0B | QUOTE));
    if plain {
        line.extend_from_slice(arg);
        return;
    }
    line.push(QUOTE);
    let mut backslashes = 0;
    for &unit in arg {
        if unit == BACKSLASH {
            backslashes += 1;
        } else {
            if unit == QUOTE {
                line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
            }
            backslashes = 0;
        }
        line.push(unit);
    }
    line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
    line.push(QUOTE);
}

#[cfg(windows)]
mod windows {
    use std::ffi::OsString;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::ExitStatusExt;
    use std::path::Path;
    use std::process::ExitStatus;
    use std::ptr::{null, null_mut};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tokio::sync::oneshot;
    use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_CONSOLE, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, ResumeThread,
        STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute,
        WaitForSingleObject,
    };

    use tracing::warn;

    use super::{Job, SpawnError, command_line};
    use crate::token::Handle;

    const TERMINATED: u32 = 1;
    const EXIT_WAIT_MILLISECONDS: u32 = 5_000;
    const EMPTY_TIMEOUT: Duration = Duration::from_secs(5);
    const EMPTY_POLL: Duration = Duration::from_millis(10);

    pub(super) fn create() -> io::Result<Handle> {
        // SAFETY: null attributes make an unnamed job whose handle is not inherited.
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Handle(job);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: limits is a JOBOBJECT_EXTENDED_LIMIT_INFORMATION of the given size.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(job)
    }

    struct Attributes(Vec<u64>);

    impl Attributes {
        fn job_list(jobs: &[HANDLE; 1]) -> io::Result<Self> {
            let mut size = 0;
            // SAFETY: a null list asks for the required size.
            unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
            let mut attributes = Self(vec![0; size.div_ceil(8)]);
            // SAFETY: the buffer is 8-byte aligned and holds size bytes.
            if unsafe { InitializeProcThreadAttributeList(attributes.list(), 1, 0, &mut size) } == 0
            {
                attributes.0 = Vec::new();
                return Err(io::Error::last_os_error());
            }
            // SAFETY: jobs outlives the list, which is deleted before the caller drops jobs.
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes.list(),
                    0,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                    jobs.as_ptr().cast(),
                    size_of_val(jobs),
                    null_mut(),
                    null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(attributes)
        }

        fn list(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.0.as_mut_ptr().cast()
        }
    }

    impl Drop for Attributes {
        fn drop(&mut self) {
            if !self.0.is_empty() {
                // SAFETY: the list was initialized and is deleted once.
                unsafe { DeleteProcThreadAttributeList(self.list()) };
            }
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct SpawnOptions<'a> {
        pub environment: Option<&'a [u16]>,
        pub new_console: bool,
        pub current_dir: Option<&'a Path>,
        pub title: Option<&'a str>,
    }

    impl SpawnOptions<'_> {
        fn flags(&self) -> PROCESS_CREATION_FLAGS {
            let environment = match self.environment {
                Some(_) => CREATE_UNICODE_ENVIRONMENT,
                None => 0,
            };
            let console = if self.new_console {
                CREATE_NEW_CONSOLE
            } else {
                0
            };
            environment | console
        }

        fn environment(&self) -> *const std::ffi::c_void {
            self.environment
                .map_or(null(), |block| block.as_ptr().cast())
        }
    }

    struct Strings {
        current_dir: Option<Vec<u16>>,
        title: Option<Vec<u16>>,
    }

    impl Strings {
        fn new(options: SpawnOptions<'_>) -> io::Result<Self> {
            Ok(Self {
                current_dir: options
                    .current_dir
                    .map(|dir| nul_terminated(dir.as_os_str().encode_wide()))
                    .transpose()?,
                title: options
                    .title
                    .map(|title| nul_terminated(title.encode_utf16()))
                    .transpose()?,
            })
        }

        fn current_dir(&self) -> *const u16 {
            self.current_dir.as_ref().map_or(null(), |dir| dir.as_ptr())
        }

        fn startup(&self, cb: u32) -> STARTUPINFOW {
            STARTUPINFOW {
                cb,
                lpTitle: self
                    .title
                    .as_ref()
                    .map_or(null_mut(), |title| title.as_ptr().cast_mut()),
                ..Default::default()
            }
        }
    }

    fn nul_terminated(text: impl Iterator<Item = u16>) -> io::Result<Vec<u16>> {
        let text: Vec<u16> = text.collect();
        if text.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a process title or directory contains NUL",
            ));
        }
        Ok(text.into_iter().chain([0]).collect())
    }

    struct Created {
        process: Handle,
        thread: Handle,
        id: u32,
    }

    fn create_process(
        application: &[u16],
        line: &[u16],
        flags: PROCESS_CREATION_FLAGS,
        options: SpawnOptions<'_>,
        strings: &Strings,
        startup: &STARTUPINFOW,
    ) -> io::Result<Created> {
        let mut line = line.to_vec();
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: all strings are NUL-terminated and outlive the call, an environment
        // block is double-NUL-terminated UTF-16 as CREATE_UNICODE_ENVIRONMENT says, the
        // startup information matches the flags, and no handles are inherited.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                0,
                flags | options.flags(),
                options.environment(),
                strings.current_dir(),
                startup,
                &mut info,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Created {
            process: Handle(info.hProcess),
            thread: Handle(info.hThread),
            id: info.dwProcessId,
        })
    }

    impl Job {
        pub fn spawn(
            self: &Arc<Self>,
            executable: &Path,
            args: &[OsString],
        ) -> Result<Process, SpawnError> {
            self.spawn_with(executable, args, SpawnOptions::default())
        }

        pub fn spawn_with(
            self: &Arc<Self>,
            executable: &Path,
            args: &[OsString],
            options: SpawnOptions<'_>,
        ) -> Result<Process, SpawnError> {
            if let Some(block) = options.environment
                && !block.ends_with(&[0, 0])
            {
                return Err(SpawnError::Process(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the environment block is not terminated",
                )));
            }
            let program: Vec<u16> = executable.as_os_str().encode_wide().collect();
            let args: Vec<Vec<u16>> = args.iter().map(|arg| arg.encode_wide().collect()).collect();
            let line = command_line(&program, &args).map_err(SpawnError::Process)?;
            let strings = Strings::new(options).map_err(SpawnError::Process)?;
            let application: Vec<u16> = program.into_iter().chain([0]).collect();
            let created = match self.create_in_job(&application, &line, options, &strings) {
                Ok(created) => created,
                Err(_) => self.create_and_assign(&application, &line, options, &strings)?,
            };
            Ok(self.watch(created))
        }

        fn create_in_job(
            &self,
            application: &[u16],
            line: &[u16],
            options: SpawnOptions<'_>,
            strings: &Strings,
        ) -> io::Result<Created> {
            let jobs = [self.handle()];
            let mut attributes = Attributes::job_list(&jobs)?;
            let startup = STARTUPINFOEXW {
                StartupInfo: strings.startup(size_of::<STARTUPINFOEXW>() as u32),
                lpAttributeList: attributes.list(),
            };
            create_process(
                application,
                line,
                EXTENDED_STARTUPINFO_PRESENT,
                options,
                strings,
                &startup.StartupInfo,
            )
        }

        fn create_and_assign(
            &self,
            application: &[u16],
            line: &[u16],
            options: SpawnOptions<'_>,
            strings: &Strings,
        ) -> Result<Created, SpawnError> {
            let startup = strings.startup(size_of::<STARTUPINFOW>() as u32);
            let created = create_process(
                application,
                line,
                CREATE_SUSPENDED,
                options,
                strings,
                &startup,
            )
            .map_err(SpawnError::Process)?;
            // SAFETY: both handles are open.
            if unsafe { AssignProcessToJobObject(self.handle(), created.process.0) } == 0 {
                let error = io::Error::last_os_error();
                // SAFETY: the process handle is open and the process has not run.
                if unsafe { TerminateProcess(created.process.0, TERMINATED) } == 0 {
                    warn!(
                        "stopping the suspended process {} failed: {}",
                        created.id,
                        io::Error::last_os_error()
                    );
                } else {
                    // SAFETY: the process handle is open.
                    unsafe { WaitForSingleObject(created.process.0, EXIT_WAIT_MILLISECONDS) };
                }
                return Err(SpawnError::Job(error));
            }
            // SAFETY: the thread handle is open.
            if unsafe { ResumeThread(created.thread.0) } == u32::MAX {
                let error = io::Error::last_os_error();
                if let Err(terminate) = self.terminate() {
                    warn!(
                        "stopping the suspended process {} failed: {terminate}",
                        created.id
                    );
                }
                return Err(SpawnError::Process(error));
            }
            Ok(created)
        }

        fn watch(self: &Arc<Self>, created: Created) -> Process {
            let Created {
                process,
                thread,
                id,
            } = created;
            drop(thread);
            let (sender, exited) = oneshot::channel();
            std::thread::spawn(move || {
                let _ = sender.send(wait_for(&process));
            });
            Process {
                job: self.clone(),
                id,
                exited,
                outcome: None,
            }
        }

        pub fn active_processes(&self) -> io::Result<u32> {
            let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            // SAFETY: info is a JOBOBJECT_BASIC_ACCOUNTING_INFORMATION of the given size.
            if unsafe {
                QueryInformationJobObject(
                    self.handle(),
                    JobObjectBasicAccountingInformation,
                    (&raw mut info).cast(),
                    size_of_val(&info) as u32,
                    null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(info.ActiveProcesses)
        }

        fn terminate(&self) -> io::Result<()> {
            // SAFETY: the job handle stays open while self lives.
            if unsafe { TerminateJobObject(self.handle(), TERMINATED) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn wait_until_empty(&self) -> io::Result<()> {
            let deadline = Instant::now() + EMPTY_TIMEOUT;
            while self.active_processes()? != 0 {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "the job still had processes {} s after it was terminated",
                            EMPTY_TIMEOUT.as_secs()
                        ),
                    ));
                }
                std::thread::sleep(EMPTY_POLL);
            }
            Ok(())
        }
    }

    fn wait_for(process: &Handle) -> io::Result<ExitStatus> {
        // SAFETY: process is an open process handle.
        if unsafe { WaitForSingleObject(process.0, INFINITE) } != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut code = 0;
        // SAFETY: process is an open process handle and code is writable.
        if unsafe { GetExitCodeProcess(process.0, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ExitStatus::from_raw(code))
    }

    #[derive(Debug)]
    pub struct Process {
        job: Arc<Job>,
        id: u32,
        exited: oneshot::Receiver<io::Result<ExitStatus>>,
        outcome: Option<Result<ExitStatus, (io::ErrorKind, String)>>,
    }

    impl Process {
        pub fn id(&self) -> u32 {
            self.id
        }

        pub async fn wait(&mut self) -> io::Result<ExitStatus> {
            if self.outcome.is_none() {
                let outcome = match (&mut self.exited).await {
                    Ok(Ok(status)) => Ok(status),
                    Ok(Err(error)) => Err((error.kind(), error.to_string())),
                    Err(_) => Err((io::ErrorKind::Other, "the wait thread ended".to_owned())),
                };
                self.outcome = Some(outcome);
            }
            match self.outcome.as_ref().expect("the outcome was just set") {
                Ok(status) => Ok(*status),
                Err((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            }
        }

        pub async fn kill(&mut self) -> io::Result<()> {
            self.job.terminate()?;
            let waited = self.wait().await.map(drop);
            let job = self.job.clone();
            let emptied = tokio::task::spawn_blocking(move || job.wait_until_empty())
                .await
                .map_err(io::Error::other)
                .and_then(|emptied| emptied);
            waited.and(emptied)
        }
    }

    impl Drop for Process {
        fn drop(&mut self) {
            if let Err(error) = self.job.terminate() {
                warn!("stopping the session's job failed: {error}");
                return;
            }
            let job = self.job.clone();
            let wait = move || {
                if let Err(error) = job.wait_until_empty() {
                    warn!("{error}");
                }
            };
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => drop(runtime.spawn_blocking(wait)),
                Err(_) => wait(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test(flavor = "multi_thread")]
        async fn a_spawned_process_gets_the_given_environment() {
            let job = Arc::new(Job::new().unwrap());
            let shell = std::path::PathBuf::from(std::env::var_os("ComSpec").unwrap());
            let environment: Vec<u16> = "GATEINTO_PROBE=7\0\0".encode_utf16().collect();
            let args = ["/d", "/c", "exit %GATEINTO_PROBE%"].map(OsString::from);
            let mut process = job
                .spawn_with(
                    &shell,
                    &args,
                    SpawnOptions {
                        environment: Some(&environment),
                        ..SpawnOptions::default()
                    },
                )
                .unwrap();
            assert_eq!(process.wait().await.unwrap().code(), Some(7));
            process.kill().await.unwrap();
        }

        #[test]
        fn an_unterminated_environment_is_refused_before_anything_starts() {
            let job = Arc::new(Job::new().unwrap());
            let shell = std::path::PathBuf::from(std::env::var_os("ComSpec").unwrap());
            let environment: Vec<u16> = "A=1\0".encode_utf16().collect();
            let error = job
                .spawn_with(
                    &shell,
                    &[],
                    SpawnOptions {
                        environment: Some(&environment),
                        ..SpawnOptions::default()
                    },
                )
                .unwrap_err();
            assert!(matches!(error, SpawnError::Process(_)), "{error}");
            assert_eq!(job.active_processes().unwrap(), 0);
        }

        #[test]
        fn creation_flags_follow_the_options() {
            let environment: Vec<u16> = "A=1\0\0".encode_utf16().collect();
            for (options, flags) in [
                (SpawnOptions::default(), 0),
                (
                    SpawnOptions {
                        environment: Some(&environment),
                        ..SpawnOptions::default()
                    },
                    CREATE_UNICODE_ENVIRONMENT,
                ),
                (
                    SpawnOptions {
                        new_console: true,
                        ..SpawnOptions::default()
                    },
                    CREATE_NEW_CONSOLE,
                ),
                (
                    SpawnOptions {
                        environment: Some(&environment),
                        new_console: true,
                        ..SpawnOptions::default()
                    },
                    CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
                ),
            ] {
                assert_eq!(options.flags(), flags, "{options:?}");
            }
        }

        #[test]
        fn the_title_is_passed_in_the_startup_information() {
            let strings = Strings::new(SpawnOptions {
                title: Some("Gateinto: office"),
                ..SpawnOptions::default()
            })
            .unwrap();
            let startup = strings.startup(size_of::<STARTUPINFOW>() as u32);
            assert_eq!(startup.cb, size_of::<STARTUPINFOW>() as u32);
            // SAFETY: lpTitle points into strings, which is alive and NUL-terminated.
            let title = unsafe { std::slice::from_raw_parts(startup.lpTitle, 17) };
            assert_eq!(String::from_utf16(title).unwrap(), "Gateinto: office\0");
            let none = Strings::new(SpawnOptions::default()).unwrap();
            assert!(none.startup(0).lpTitle.is_null());
        }

        #[test]
        fn a_nul_in_the_title_or_directory_is_refused_before_anything_starts() {
            let job = Arc::new(Job::new().unwrap());
            let shell = std::path::PathBuf::from(std::env::var_os("ComSpec").unwrap());
            let directory = std::path::PathBuf::from("C:\\a\0b");
            for options in [
                SpawnOptions {
                    title: Some("a\0b"),
                    ..SpawnOptions::default()
                },
                SpawnOptions {
                    current_dir: Some(&directory),
                    ..SpawnOptions::default()
                },
            ] {
                let error = job.spawn_with(&shell, &[], options).unwrap_err();
                assert!(matches!(error, SpawnError::Process(_)), "{error}");
            }
            assert_eq!(job.active_processes().unwrap(), 0);
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn a_spawned_process_starts_in_the_given_directory() {
            let job = Arc::new(Job::new().unwrap());
            let shell = std::path::PathBuf::from(std::env::var_os("ComSpec").unwrap());
            let directory = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap());
            let args = ["/d", "/c", "if /i %CD%==%SystemRoot% exit 3"].map(OsString::from);
            let mut process = job
                .spawn_with(
                    &shell,
                    &args,
                    SpawnOptions {
                        current_dir: Some(&directory),
                        ..SpawnOptions::default()
                    },
                )
                .unwrap();
            assert_eq!(process.wait().await.unwrap().code(), Some(3));
            process.kill().await.unwrap();
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn the_suspended_fallback_runs_the_process_inside_the_job() {
            let job = Arc::new(Job::new().unwrap());
            let shell = std::env::var_os("ComSpec").unwrap();
            let program: Vec<u16> = shell.encode_wide().collect();
            let args: Vec<Vec<u16>> = ["/c", "ping -n 60 127.0.0.1 >NUL"]
                .iter()
                .map(|arg| arg.encode_utf16().collect())
                .collect();
            let line = command_line(&program, &args).unwrap();
            let application: Vec<u16> = program.into_iter().chain([0]).collect();
            let options = SpawnOptions::default();
            let strings = Strings::new(options).unwrap();
            let created = job
                .create_and_assign(&application, &line, options, &strings)
                .unwrap();
            let mut process = job.watch(created);
            assert!(job.active_processes().unwrap() >= 1);
            process.kill().await.unwrap();
            assert_eq!(job.active_processes().unwrap(), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn line(executable: &str, args: &[&str]) -> io::Result<String> {
        let args: Vec<Vec<u16>> = args.iter().map(|arg| wide(arg)).collect();
        let mut line = command_line(&wide(executable), &args)?;
        assert_eq!(line.pop(), Some(0));
        Ok(String::from_utf16(&line).unwrap())
    }

    #[test]
    fn the_executable_is_quoted_and_plain_arguments_are_kept() {
        assert_eq!(
            line(r"C:\Program Files\Edge\msedge.exe", &["a", "--flag=1"]).unwrap(),
            r#""C:\Program Files\Edge\msedge.exe" a --flag=1"#
        );
    }

    #[test]
    fn arguments_are_quoted_for_the_microsoft_c_runtime() {
        for (arg, quoted) in [
            ("a b", r#""a b""#),
            ("", r#""""#),
            ("a\tb", "\"a\tb\""),
            (r#"a"b"#, r#""a\"b""#),
            (r"a\b", r"a\b"),
            (r"C:\a b\", r#""C:\a b\\""#),
            (r#"a\"b"#, r#""a\\\"b""#),
            (r#"a\\"b c"#, r#""a\\\\\"b c""#),
        ] {
            assert_eq!(
                line("x", &[arg]).unwrap(),
                format!("\"x\" {quoted}"),
                "{arg}"
            );
        }
    }

    #[test]
    fn nul_and_a_quoted_executable_are_refused() {
        for (executable, arg) in [("x", "a\0b"), ("x\0", "a"), ("x\"y", "a")] {
            let error = line(executable, &[arg]).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{executable:?}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn jobs_are_unavailable_outside_windows() {
        assert_eq!(Job::new().unwrap_err().kind(), io::ErrorKind::Unsupported);
    }
}
