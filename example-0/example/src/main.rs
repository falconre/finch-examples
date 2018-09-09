#[macro_use] extern crate error_chain;
extern crate falcon;
extern crate finch;

// We use error chain to encapsulate the different types of errors we may
// encounter.
pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Falcon(::falcon::error::Error);
            Finch(::finch::error::Error);
            Io(::std::io::Error);
        }
    }
}

use error::*;

use finch::executor::{Driver, Memory, State};
use finch::platform::Dummy;
use falcon::il;
use falcon::loader::Loader;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;


/// The function, "Drives," a state to a specified address.
///
/// This is a common function you will use while symbolically-executing snippets
/// of disassembly. It takes multiple drivers, and drives them until a certains
/// number of steps are executed. When a driver reaches the desired address, it
/// is saved. When a driver reaches a, "Kill," address, it is dropped and no
/// longer tracked.
fn drive_to(
    mut drivers: Vec<Driver<Dummy>>,
    address: u64,
    steps: usize,
    kill_addresses: &HashSet<u64>
) -> Result<Vec<Driver<Dummy>>> {

    // A Vec to hold our finished drivers, which have reached the target
    // address.
    let mut collect_drivers = Vec::new();

    for _i in 0..steps {
        // If we are out of drivers to step, we're done.
        if drivers.len() == 0 {
            break;
        }

        // A temporary vec to hold drivers for this step
        let mut step_drivers = Vec::new();

        // Loop through the drivers we need to stop
        for driver in drivers {
            // As you debug your symbolic executors, this is a great place to
            // watch what's happening, and see the last instruction which
            // executed before something failed.
            // if let Some(instruction) = driver.instruction() {
            //     println!("{}", instruction);
            // }

            // Add all of the drivers which resulted from this step to our
            // temporary vec of drivers.
            step_drivers.append(&mut driver.step()?);
        }

        // Zero our our drivers.
        drivers = Vec::new();

        // Loop through all of our drivers for this step.
        for driver in step_drivers {

            // If we have an address for this driver (this driver is currently
            // sitting on an instruction),
            if let Some(driver_address) = driver.address() {
                // Don't add this driver to anything if it's in our kill set.
                if kill_addresses.contains(&driver_address) {
                    continue;
                }
                // If this driver is on our target address, add it to our
                // result drivers.
                if driver_address == address {
                    collect_drivers.push(driver);
                    continue;
                }
            }
            // Add this driver back to our drivers we're going to process in
            // the next step.
            drivers.push(driver);
        }
    }

    // Return the drivers which reached the target address.
    Ok(collect_drivers)
}


fn run() -> Result<()> {
    let arguments = ::std::env::args().into_iter().collect::<Vec<String>>();

    // Let's load our target binary
    let filename =
        arguments
            .get(1)
            .ok_or("Missing path to target binary")?;

    let path = Path::new(filename);

    // We now have a Falcon Elf file.
    let elf = falcon::loader::Elf::from_file(path)?;

    // While we're here, let's open a file containing our desired shellcode
    let filename =
        arguments
            .get(2)
            .ok_or("Missing path to desired shellcode")?;

    let path = Path::new(filename);

    let mut shellcode_bytes: Vec<u8> = Vec::new();
    let mut file = File::open(path)?;
    file.read_to_end(&mut shellcode_bytes)?;

    // Let's start my initializing memory.
    let mut memory =
        Memory::new_with_backing(elf.architecture().endian(),
                                 falcon::RC::new(elf.memory()?));

    // At this point, we need to pick addresses for where we will place things
    // in memory. Our stack will go from 0xb0001000 to 0xb0000000.
    const STACK_BASE: u64 = 0xb000_0000;
    for i in 0..4096 {
        memory.store(STACK_BASE + i, &il::expr_const(0, 8))?;
    }

    // We'll set our stack pointer in the middle of this, at 0xb000_0800.
    const STACK_POINTER: u64 = 0xb000_0800;

    // And our first byte of input was stored at [rsp+0x7], so let's drop it
    // into memory there.
    memory.store(STACK_POINTER + 0x7, &il::expr_scalar("i-0", 8))?;

    // Now we need to pick an address for our shellocde. 0xa000_0000 is as good
    // as any.
    const SHELLCODE_BASE: u64 = 0xa000_0000;
    for i in 0..4096 {
        // Remember, our first byte of input is on the stack, so we'll name
        // these variables starting with "i-1".
        memory.store(SHELLCODE_BASE + i,
                     &il::expr_scalar(format!("i-{}", i + 1), 8))?;
    }

    // Now we can create our symbolic state.
    let mut state = State::new(memory, None);

    // Set our stack pointer
    state.set_scalar("rsp", &il::expr_const(STACK_POINTER, 64))?;

    // rbx points to our shellcode
    state.set_scalar("rbx", &il::expr_const(SHELLCODE_BASE, 64))?;

    // rax is equal to the number of bytes we read in. We'll set this to
    // 256
    const SHELLCODE_LEN: usize = 256;
    state.set_scalar("rax", &il::expr_const(SHELLCODE_LEN as u64, 64))?;

    // Our Driver needs a program to drive over, so we can go ahead and tell
    // Falcon to lift the binary.
    //
    // We must ensure our target function, and more specifically, the
    // instruction we wish to lift, is in out target program. Finch will
    // automatically lift further functions as needed.
    //
    // A simple elf.program() would work fine here, since we have a symbol for
    // main. program_recursive() recursively follows direct,
    // interprocedural-type branches, and lifts those as functions as well.
    let program = elf.program_recursive()?;

    // Now we need a program location where our starting instruction is.
    const START_ADDRESS: u64 = 0x64d;
    let program_location: il::ProgramLocation =
        il::RefProgramLocation::from_address(&program, START_ADDRESS)
            .ok_or("Unable to find START_ADDRESS in program")?
            .into();

    // We can go ahead and create our driver
    let driver = Driver::new(
        program.clone(),
        program_location,
        state,
        falcon::RC::new(elf.architecture().box_clone())
    );

    // And now we drive to our stop address.
    const STOP_ADDRESS: u64 = 0x693;
    let drivers = drive_to(vec![driver], STOP_ADDRESS, 100000, &HashSet::new())?;

    // We should only have one driver
    if drivers.len() != 1 {
        bail!("Expected 1 driver, but found {} drivers", drivers.len());
    }

    let mut driver = drivers[0].clone();

    // Let's get the state from this driver.
    let state = driver.state_mut();

    // Take a look some expressions for our shellcode
    println!("{}", state.memory().load(SHELLCODE_BASE, 8)?.unwrap());
    println!("{}", state.memory().load(SHELLCODE_BASE + 1, 8)?.unwrap());
    println!("{}", state.memory().load(SHELLCODE_BASE + 2, 8)?.unwrap());

    // We will enforce our desired shellcode over what's in memory
    for i in 0..shellcode_bytes.len() {
        let address = SHELLCODE_BASE + i as u64;
        let byte_expr =
            state.memory()
                .load(address, 8)?
                .ok_or(format!("No shellcode at address 0x{:x}?", address))?;
        state.add_path_constraint(
            &il::Expression::cmpeq(
                byte_expr,
                il::expr_const(shellcode_bytes[i] as u64, 8)
            )?
        )?;
    }

    // No we will solve for the bytes we need to send, one at a time.
    // We also need the byte that comes immediately after our shellcode, so our
    // loop is +2 for the initial byte, all of our shellcode, and the trailing
    // byte.
    let mut bytes: Vec<u8> = Vec::new();
    for i in 0..(shellcode_bytes.len() + 2) {
        let input_byte = state.eval_and_concretize(
            &il::expr_scalar(format!("i-{}", i), 8))?;
        let input_byte =
            input_byte.ok_or(format!("No satisfiable value for i={}", i))?;
        bytes.push(input_byte.value_u64().unwrap() as u8);
        println!("{}: {:02x}", i, input_byte.value_u64().unwrap());
    }

    // And we're all done! Print out the final result
    println!("{}",
        bytes.into_iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(""));

    Ok(())
}


fn main() {
    match run() {
        Ok(_) => {},
        Err(e) => {
            eprintln!("error: {}", e);
            for e in e.iter().skip(1) {
                eprintln!("caused by: {}", e);
            }
            if let Some(backtrace) = e.backtrace() {
                eprintln!("backtrace: {:?}", backtrace);
            }
        }
    }
}