# KERNEL INJECTOR
Przemysław Lenart <przemek.lenart@gmail.com>

v. 0.2, 2013

## Description

Kernel Injector is a Linux kernel module created for injecting faults into
kernel's address space. It registers procfs file in /proc/kernelinjector 
which is used to pass commands and get optional information or results.
User is obligated to pass a full command to the write function which can
be terminated with any of control characters (such as '\n', '\0'...).
Command is a list of a attributes and values (which can be optional):

    ATTRIBUTE1 value1 ATTRIBUTE2 ATTRIBUTE3 value3 ...

Order of attributes passed to command is not important.

## Attributes

Some attributes require other attributes to work. All dependencies are listed
in descriptions. Currently supported attributes:

* `TRIGGER symbol` - specify a trigger symbol for an injection. Injection is
done only when symbol is executed by a processor. Symbol can have a textual
form such as function name or can be a hexadecimal number preceded by 
hexadecimal prefix '0x'.

* `MODULE module_name` - specify module name which is required when injecting in
module's data.

* `INJECT_INTO symbol` - specify a symbol for an injection. If TRIGGER is 
specified injection is done when it's fired, otherwise injection is executed 
immediately. Symbol can have a textual form such as function name or can be a
hexadecimal number preceded by hexadecimal prefix '0x'. Injection specifier such
as: BITFLIP is also required.

* `BITFLIP x` - Injection is based on a bit flip. One bit of sequence of x bytes
after injection address is inverted. 'x' is a decimal number. Require: 
INJECT_INTO.

* `STACK` - Inject into stack using bit flip. Require: TRIGGER.

* `REGS` - Inject into registers using bit flip. Require: TRIGGER.

* `DATA` - Inject into module's static data segment using bit flip. 
Require: MODULE.

* `RODATA` - Inject into module's read only static data segment using bit flip. 
Require: MODULE.

* `CODE` - Inject into module's code segment using bit flip. Require: MODULE.

* `INJECT_OFFSET offset` - Specify offset for an inject symbol. 'offset' is a
decimal number. Can be negative. Require INJECT_INTO.

* `TRIGGER_OFFSET offset` - Specify offset for a trigger symbol. 'offset' is a
decimal number. Can be negative. Require TRIGGER.

* `CLEAR` - clear all trigger based injections. If CLEAR is specified all
other keywords are ignored.

* `MAX_INJECTIONS number` - specify maximum number of injections in trigger
based injections. 'number' is decimal value. Zero value (default one)
means that injections are executed indefinitely. Must be positive value.
Require TRIGGER.

* `SKIPPED_INJECTIONS number` - specify number of skipped injections. For
example when number is 10, eleventh call will trigger injection. Must be
decimal positive value. Require TRIGGER.

* `DEBUG` - prevents from actual fault injections.

## Examples

Command can be passed for example by bash's echo command:

`echo "SOME COMMAND..." > /proc/kernelinjector`

There are some example commands:

* `INJECT_INTO 0xffffffffa0de4590 BITFLIP 10` - invert one random bit in a 
sequence of 10 bytes after 0xffffffffa0de4590.

* `TRIGGER my_function TRIGGER_OFFSET 32 INJECT_INTO my_state_var BITFLIP 1` -
when an instruction placed 32 bytes after my_function is executed inject into
my_state_var chaning randomly one bit in first byte.

* `MODULE ext4 CODE RODATA DATA` - revert 1 bit in code segment, 1 bit in 
static data segment and 1 bit in read only static data segment.

## /proc/kernelinjector output

First line in an output is a state of last issued command. When user passed
incorrect command due to bad semantics or syntax there will be description
which may help with resolving problem:

    column_number: result_string

Column number indicates position of parse errors. If operation is successful
result_string will be `OK`.

If more lines are present they will be showing state of trigger based
injections. It's good to know that ALL TRIGGER BASED INJECTIONS MUST BE
CLEARED to be sure that they are not using kprobe mechanizm anymore. One
line is reserved for one trigger based injection:

    TRIGGER 0x%lx (%s+%ld) CALLS %ld/%ld\n

1. Trigger address with added offset
2. Symbol name of a trigger, "?" if not availible.
3. Decimal trigger offset
4. Number of completed injections
5. Maximum number of injections

## Syslog output

All injections are registered in a syslog. Every injection starts with:

    --- INJECTION START ---

and ends with:

    --- INJECTION END ---

Between these lines detailed information about injection is described. If
there is a trigger:

    \tTRIGGER 0x%lx (%s+%ld)\n

1. Trigger address
2. Trigger symbol name
3. Decimal trigger offset

Every injection is based on bit flipping. Information about bitlip is also
presented:

    \tBITFLIP 0x%lx:%d (%pF)\n

1. Address of bit flipped byte
2. Reverted bit number from 0 to 7
3. Address of bit flipped byte in kernel pointer format

If you are injecting into registers, randomly selected register is also
listed:

    \tREG: %s\n

1. Register name. For example: RAX, CS, FLAGS

There are other messages which can be shown in syslog:

* `\tTARGET 0x%lx (%s+%ld)\n"` - the same syntax as in TRIGGER
* `\tSTACK 0x%lx:%ld\n` - will be injectiong into stack
* `\tDATA 0x%lx:%ld\n` - will be injecting into module's static data segment
* `\tRODATA 0x%lx:%ld\n` - will be injeting into module's read only static data segment
* `\tCODE 0x%lx:%ld\n` - will be injecting into module's code segment

Explanation of:

    0x%lx:%ld

1. Segment address
2. Segment size (for stack it fixed to 10)

### Output example

    --- INJECTION START ---
        TRIGGER 0xffffffffa01898aa (ext4_getattr+10)
        TARGET 0xffffffffa01898af (ext4_getattr+15)
        BITFLIP 0xffffffffa01898b7:7
    --- INJECTION END ---



