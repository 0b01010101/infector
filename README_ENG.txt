The virus infects files (ELF: EXEC, DYNAMIC, x86-64) only in the current directory, without changing their size, replacing the address of the function call.
    Launches a new process with a payload - SURPRISE, which runs as a child.
    Transfers control to the original code.
*changes the sizes of segments and sections
*may not completely infect the file, but this should not affect the correct operation of the file
*encrypts (changes) all code except START_LOADER
;---------------------------------------------------------------------------------------------------------------------------------------------------------
   The hello file has been modified at addresses (offsets in the file):
      0x0e - 0xAA (a label that indicates that the file is infected)
      0x114c - substitution of function address (command 'call offs'(0xbytebytebytebyteE8), replaced by 0x0000002FE8)
      0x618 - SURPRISE(payload, code that will be run in a separate process),
      0x20ec - MAIN_LOADER (the main part of the shell code that infects files, launches SURPRISE)
      0x1180 - START_LOADER (the smallest part of shell code that is hidden in the EXECUT segment, providing loading, control transfer, MAIN_LOADER)
SURPISE - size==0x10 bytes; located in the section: LOAD, NOEXECUT;
MAIN LOADER - size==0xcb0(3248) bytes; located in the section: LOAD, NOEXECUT(NOT THE SAME AS SURPRISE);
START LOADER - size==0x4c(76) bytes; located in the section: LOAD, EXECUT;
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------
The virus code is called by the first command ('CALL':0x..E8 or 'CALLN':0x..15ff or 'CALLF':0x..16ff) of the original code, START_LOADER is launched...
    START_LOADER : allocates memory, decrypts MAIN_LOADER and starts it
    MAIN_LOADER: 1. looks for a file, if it is not there, then jumps to point 3;
                   2. infects (or tries to) the file and jumps to point 1;
                   3. creates a child process with the code SURPRIZE
                   4. jumps to the original code (to the address that the substituted function should have called) - puts the address on the stack + ret
   ORIGINAL CODE: ...
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                START_LOADER:
1. Copies the return address from the stack to rax;
2. Saves some registers (rdi, rsi, rdx, rcx)
3. Allocates 8kb of memory for decryption and launching MAIN LOADER, calling syscall-'brk()' twice (the first time - finds out the starting address for memory allocation;
       The second time - 'allocates memory' moves the starting address by 8kb
4. Gives the allocated memory size 8kb access rights to: read, write, execute
5. Copies the return address in rsi from the stack (as in step 1.) and puts it on the top of the stack for further copying it to r13 in MAIN_LOADER
    !!! The return address from the START LOADER function is needed to calculate the virtual addresses of the code mapped into memory by the Linux boot loader
    !!! Return address from the START LOADER function + offset in the file == desired code address in the process virtual memory
    !!! the offset is calculated when a file is infected as: return address - address of the required code (r13 - adr code)
6. Copies and decrypts the MAIN LOADER code from the LOAD READ segment into the allocated memory code
7. Transfers control to allocated memory with execution rights (MAIN LOAD) with the 'jmp rdi' command
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------
                                       MAIN_LOADER:
IN: rdi - address of allocated memory of 8kb size with code MAIN LOADER; edx - key for decrypting MAIN LOADER and SURPISE in the CURRENT file;
       [rsp-8] - return address from START LOADER

1. Saves the remaining registers on the stack; copies: [rsp-8] to r13, rdi to rbp, edx to r12d;
    !!! r13, rbp, r12 - play a key role in infection (function '_infect') and are not changed in MAIN_LOADER
2. Opens the current directory (function '_dir_open', name: '.')
3. Reads the directory (function '_dir_read'), if the directory is empty, then performs step 5.
4. Starts analyzing files in the current directory by calling the 'read_files' function:
    4.1 Checks the executable file or directory, if not, then follows step 4.1
    4.2 If the file is a directory, then inf_dir is executed (does nothing),
        If the file is an executable file, then inf_file is executed,
        If the file is something else, then it returns to the beginning of 'read_files' (section 4.1)
       ('inf_file'):
       4.2.1 Check the access rights of the infected file (whether the owner can execute it) and find out its size after calling the '_file_stat' function
             If the file is not executable, then perform step 4
       4.2.2 The file is infected with the '_infect' function --- !!!read more for detailed description!!!
       4.2.3 Jumps to 'nxt_file', where it either executes step 4.1 or completes 'read_files'
    4.3 Complies with point 3.
5. Runs the payload code (SURPRIZE)(function '_start_payload')
    5.1 Creates a new process syscall'fork()'
    5.2 In the new process, after the SURPRISE code has completed executing, syscall'exit' is executed
6. Pops all saved registers from the stack (ALL except rax)
7. Places the address (r13+OFFS_OF_ORIG_CODE) of the code that should have been executed instead of START_LOADER on the top of the stack, and transfers
    execution to it with the 'ret' command
;-----------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                                      _infect:
1. Opens the infected file (function '_file_open')
2. Displays the file in memory (function '_mmap')
3. Analyzes the file headers (the 'check_exec' function), checking it for correctness and saving some values in registers; if the file is incorrect,
then it executes step 10.:
    rdi - address of the beginning of the file in memory; si - e_pnum; dx - e_shnum; r10 - e_phoff; r11 - e_shoff;
4. Analyzes the file segments and fills in the segment bitmap in r9 (function 'check_seg'). The bit number is the segment number; if the bit is set,
then the segment is LOAD.
       Holds only 32 segments! From 0-31 bits - READ/READandWRITE segments. C 32-63 bits - EXECUT segments.
5. Checks whether the file is infected or not (function 'check_infected'), if infected ([rdi+14]==0xAA), then executes step 10.
6. Copies SURPRISE to the infected file from the current file:
    6.1 Takes the code at address r13+OFFS_SURPRISE and copies it, decrypting (function 'xor_code') with key (r12), into memory
allocated in START LOAD (address in rbp)+0x1000
    6.2 Changes the key to a new one (mov r12, rbp). !!! All code is encrypted with an address that is stored in rbp (memory allocated in START_LOADER)!!!
    6.3 Copies the SURPRISE code into the infected file (function 'infect_shell_data'), if unsuccessful, then executes step 10.
       !!!The memory address from which SURPRISE begins in the infected file is stored in r14!!!
    6.4 Encrypts SURPRISE in the infected file with a new key ('xor_code')
    6.5 Changes the size of the segment and sections (sections) in the headers of the infected file
7. Copies MAIN_LOADER to the infected file from the current one:
    7.1 Copies the MAIN_LOADER code from the memory allocated in START_LOADER (from where it is currently being executed) to the infected file (function 'infect_shell_data')
        If it fails, then step 10. !!!The memory address from which MAIN_LOADER begins in the infected file is stored in r15!!!
    7.2 Changes the size of the segment and sections (sections) in the headers of the infected file
    7.3 (Function substitution - 'find_entr') Searches in the original code (ORIGINAL CODE) 'CALL' or 'CALLN' or 'CALLF', the address of which can be
replaced with START_LOADER
         Returns to rbx the address (! in memory) of the next command after 'CALL...'; if it does not find it, then execute step 10.
          !!! the address in rbx is the SAME address that will be in r13 when the infected file is LAUNCHED!!!
    7.4 Calculates the offset in the infected file, from the next command after the substituted function (clause 7.3) to SURPRISE - (sub r14, rbx\n mov r14, rbx)
    7.5 Changes the MAIN_LOADER code in the infected file:
       7.5.1 Changes the address OFFS_SURPRISE(cur_add: mov rsi, r13\n mov rcx, OFFS_SURPRISE), which is used in paragraph 6.1 when the infected file is executed
       7.5.2 Changes the address ADDR_OF_SURPRISE_CODE(curr_add_stpay: mov eax, ADDR_OF_SURPRISE_CODE), which is used in the MAIN_LOADER: 5. clause, when the infected file is executed
       7.5.3 Changes the address OFFS_OF_ORIG_CODE(ml_exit: mov ebx, OFFS_OF_ORIG_CODE), which is used in the MAIN_LOADER: 7. clause, when the infected file is executed
       7.5.4 Changes 4 bytes of code in MAIN_LOADER(ml_exit: ...\n add rax, rbx\n 0xXXXXXXXX):
              If the opcode 'CALL' (0xE8) was detected in paragraph 7.3 - changes to "cmp rax, 0"
              If in paragraph 7.3 the opcode 'CALLF'/'CALLN'(0xFF, mod==3/2) was detected - changes to "mov rax, [rax]"
8.Copies START_LOADER to the infected file from the current one:
    8.1 Copies (collects/clears from 'jmp') code (function 'collect_shell_exec')START_LOADER from the current file to the buffer (rbp+0x1000 as before)
    8.2 Copies the code (the 'infect_shell_exec' function changes the sizes of segments/sections)START_LOADER from the buffer (the address of which is returned by the 'collect_shell_exec' function) into the infected file
       If it fails, then step 10. !!!The memory address from which START_LOADER begins in the infected file is stored in rbx!!!
    8.3 Calculates the offset in the infected file, from the next command after the substituted function (clause 7.3) to START_LOADER - (xchg r13, r14\n...sub rbx, r13)
    8.4 Changes the address OFFS_START_LOAD(cur_add1: mov ebx, OFFS_START_LOAD), which is used in paragraph 8.1 when the infected file is executed
    8.5 In the original code, we change the offset of the 'call' jump (which was found in paragraph 7.3) to the offset obtained in (rbx) paragraph 8.3
9. Encrypt the infected file MAIN_LOADER with the r12 key
10. Close the infected file (function '_file_close')
;-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                       infect_shell_exec:
1. Gets from r9(31-63bits) the number of the segment that LOAD EXECUT
2. Calculates the address of the beginning of the desired header in memory
3. Searches for free space (minimum 8bytes) in the segment and writes code there, changing the size of the segment and sections (function 'nork_in_segment'):
    3.1 Finds the address and size of the section that is located in the desired segment
    3.2 Searches for free space and writes code (or part of it) there (function 'find_nork').
          'find_nork' uses the table 'tab_code_len' in which the index is the number of the START_LOADER command, and the byte value at the index is the size of the START_LOAd command in bytes
          'tab_code_len' is located in the function code 'nork_in_segment'
    3.3 Changes the size of a segment and section if in the previous paragraph the code was written to a section of the infected file
    3.4 If the code has ended or the sections in this segment have ended, then exits 'nork_in_segment' (Goes to step 4.), otherwise executes step 3.1
4. If the code that needs to be implemented has ended or the LOAD EXECUT sections have run out, then exits the function
    If not, then follow step 2
;-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                          find_nork:
1. Searches the section for empty(0x00) 8bytes("norks") or more. If the section or code has ended, it exits the function.
    !!!Format "norks" == commandcommand... + far/close jmp + ret !!!
2. If this is the first call, then perform step 3., otherwise:
    2.1 Checks the distance from the last START_LOADER code command written earlier into the infected file to the memory area into which new commands will now be written.
    2.2 If the distance is within -125 to 125, then changes the far jmp in the previous "norks" to the near jmp and adds commands ('write_shell') if they
interfere with "norks"
    2.3 Writes the jump address in the previous "norks" to the current "norks"
3. Writes the code START_LOADER + far jmp + ret to the current "norks" (function 'write_shell')
4. If the code runs out, then exits 'find_nork', otherwise executes step 1.
;-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
                                          write_shell:
1. Checks how many commands will fit into “norks”, taking into account that the far jmp takes 5 bytes, the near one 2+ret. (Far jmp can be replaced with
near jmp only in clause find_nork:2.2)
2. Copies the START_LOADER code from “item _infect:8.1” into the infected file, byte byte
    + searches by signature for places in START_LOADER where the key and OFFS_ML are copied (mov edx, 0xkey and mov eax, OFFS_ML). Inserts the necessary
data into these places in the code:
    key - rbp; offs - sub r15, r13
3. Selects which jmp to add “norks” to the end
4. Exits the function
;-------------------------------------------------------------------------------------------------------------------------------------------------------------------------
