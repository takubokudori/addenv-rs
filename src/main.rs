use winapi::um::processenv::GetEnvironmentVariableA;
use winapi::um::errhandlingapi::GetLastError;
use std::ffi::CString;
use winapi::um::winreg::{RegOpenKeyExA, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RegSetValueExA, RegCloseKey};
use std::cell::Cell;
use winapi::shared::minwindef::HKEY;
use winapi::um::winnt::{REG_SZ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, KEY_WRITE};
use clap::{App, Arg};
use winapi::shared::winerror::{ERROR_ENVVAR_NOT_FOUND, ERROR_ACCESS_DENIED};

fn get_env_var(name: CString) -> Result<String, u32> {
    unsafe {
        let mut ret: Vec<u8> = Vec::with_capacity(128);
        let mut nb = GetEnvironmentVariableA(name.as_ptr() as *const i8,
                                             ret.as_mut_ptr() as *mut i8,
                                             128);
        if nb == 0 && GetLastError() == ERROR_ENVVAR_NOT_FOUND {
            return Ok("".to_string());
        }

        while nb > ret.capacity() as u32 {
            ret = Vec::with_capacity(nb as usize);
            ret.set_len(0);
            nb = GetEnvironmentVariableA(name.as_ptr() as *const i8,
                                         ret.as_mut_ptr() as *mut i8,
                                         nb);
            ret.set_len(nb as usize);
        }

        match String::from_utf8(ret) {
            Ok(x) => Ok(x),
            Err(_) => Err(1)
        }
    }
}

fn set_env_var(name: CString, value: CString, is_system: bool) -> Result<(), u32> {
    let reg_str = if is_system {
        CString::new("System\\CurrentControlSet\\Control\\Session Manager\\Environment").unwrap()
    } else {
        CString::new("Environment").unwrap()
    };
    let hkey_area = if is_system { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
    unsafe {
        let hkey: Cell<HKEY> = Cell::new(std::mem::zeroed());

        let e = RegOpenKeyExA(hkey_area,
                              reg_str.as_ptr(),
                              0,
                              KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | KEY_WRITE,
                              hkey.as_ptr());
        if e != 0 { return Err(e as u32); }

        let e = RegSetValueExA(hkey.get(),
                               name.as_ptr(),
                               0,
                               REG_SZ,
                               value.as_ptr() as *const u8,
                               value.to_bytes().len() as u32 + 1);
        if e != 0 { return Err(e as u32); }
        RegCloseKey(hkey.get());
        Ok(())
    }
}

pub fn is_exists(value: &str, pat: &str) -> bool {
    let temp = value.to_lowercase();
    let pt = pat.to_lowercase();
    let v: Vec<&str> = temp.split(';').collect();
    for s in v {
        if s == pt { return true; }
    }
    false
}

fn main() {
    let app = App::new("addenv")
        .version("1.0.0")
        .about("Add an environment variable")
        .arg(Arg::with_name("name")
            .help("environment variable name")
            .required(true)
        )
        .arg(Arg::with_name("value")
            .help("environment variable value")
            .required(true)
        )
        .arg(Arg::with_name("is_system")
            .help("system environment variable")
            .short("s")
            .long("system")
        )
        .arg(Arg::with_name("print")
            .help("Print debug string")
            .short("p")
            .long("print-debug")
        )
        .arg(Arg::with_name("duplicated")
            .help("allow duplicated values")
            .short("d")
            .long("allow-duplicated")
        );

    let matches = app.get_matches();

    let name = matches.value_of("name").unwrap();
    let value = matches.value_of("value").unwrap();
    let is_system = matches.is_present("is_system");
    let allow_duplicated = matches.is_present("duplicated");
    let is_debugging = matches.is_present("print");
    if is_debugging {
        println!("name: {}", name);
        println!("value: {}", value);
    }
    let mut new_val = match get_env_var(CString::new(name).unwrap()) {
        Ok(x) => x,
        Err(ERROR_ENVVAR_NOT_FOUND) => "".to_string(),
        Err(x) => { panic!("Failed to get environment variable: {}", x); }
    };
    if is_debugging { println!("{} = {}", name, new_val); }

    if !allow_duplicated && is_exists(&new_val, value) {
        println!("{} already exists in {}", value, name);
        return;
    }
    if new_val.len() != 0 && !new_val.ends_with(";") { new_val += ";"; }
    new_val += value;

    if is_debugging { println!("new value: {}", new_val); }

    match set_env_var(CString::new(name).unwrap(),
                      CString::new(new_val).unwrap(),
                      is_system) {
        Ok(_) => {
            println!("Environment variable added successfully");
        }
        Err(ERROR_ACCESS_DENIED) => {
            println!("You need privileges");
        }
        Err(x) => {
            println!("Failed to add environment variable: {}", x);
        }
    }
}

#[test]
fn test() {
    fn assert_a(a: &str, patterns: Vec<&str>, expected: bool) {
        for pat in patterns {
            assert_eq!(is_exists(a, &pat.to_string()), expected);
        }
    }

    let a = "helLo;world;gOod;nice";
    let patterns = vec!["hello", "world", "good", "nice", "HelLo", "hElLo", "GOOD"];
    assert_a(&a, patterns, true);
    let patterns = vec!["bad", "hello2", "hell", "hallo"];
    assert_a(&a, patterns, false);
}