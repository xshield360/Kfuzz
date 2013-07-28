#--
#
# Description: kfuzz (beta)
#
# Author: Levle
#
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
#IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
#INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT 
#NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
#PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
#WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
#ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
#POSSIBILITY OF SUCH DAMAGE.
#
#
#--

from optparse import OptionParser
from random import randrange
from sys import exit
from subprocess import Popen,PIPE
from ctypes import *
from ctypes import wintypes
from win32con import NULL,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING
from win32file import INVALID_HANDLE_VALUE
from win32api import GetLastError
(kernel32,ntdll) = (windll.kernel32,windll.ntdll)
DeviceIoControl = windll.ntdll.ZwDeviceIoControlFile

dwords = [0x00000000,0x00001000,0x0000FFFF,0xFFFFFFFF,0xFFFF0000]

class build:
	def return_len(self,case):
		if (randrange(0,1) == 0):
			length = len(case)
		else:
			length = len(case)+randrange(-0xFFFF,0xFFFF)
		return length
	def return_addr(self,case,io):
		style = randrange(0,3)
		if (style == 0 and io == 0):
			memObj = MemMgt().mapPageMem(randrange(0xFF,0xFFFF))
			kernel32.WriteProcessMemory(-1,memObj[0],str(case),len(case),byref(c_int(0)))
			address = memObj[0]
		elif (style == 0 and io == 1):
			memObj = MemMgt().mapPageMem(randrange(0xFF,0xFFFF))
			address = memObj[0]
		if (style == 1):
			address = dwords[randrange(0,4)]
		if (style == 2):
			address = randrange(0x80000000,0xFFFFFFFF)
		if (style == 3):
			address = randrange(0x00000000,0x7FFFFFFF)
		return hex(address)

class mutate:
	def format(self):
		char = ['x','d','h','n']
		return "%s%i%s" % ('%',randrange(0,0xFF),char[randrange(0,3)])

	def strings(self):
		letters = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
		return letters[randrange(0,26)]*randrange(0,0xFF)

	def special(self):
		char =['!','@','#','$','%','^','&','*','(',')','_','+','-','=','[',']','\\','{','}','|',';',':','.','/','<','>','?','`','~',"\"","\'"]
		return char[randrange(0,30)]*randrange(0,0xFF)

	def num(self):
		return randrange(0,0xFF)-randrange(0,0xFF)+round(random.random())

	def dword(self):
		return dwords[randrange(0,4)]*randrange(0,0xFF)

class MemMgt:
	def ntalloc(self,addr,size):
		return ntdll.NtAllocateVirtualMemory(-1,byref(c_int(hex(addr))), 0x0,byref(c_int(size)),0x1000|0x2000,0x40)	

	def zalloc(self):
		ntdll.NtAllocateVirtualMemory(-1,byref(c_int(0x1)), 0x0,byref(c_int(0x1000)),0x1000|0x2000,0x40)
		return kernel32.WriteProcessMemory(-1, 0x1, "\x41"*1000, 0x1000, byref(c_int(0)))

	def mapPageMem(self,size):
		hMap = kernel32.CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,0x40,0,size,NULL)
		addr = kernel32.MapViewOfFileEx(hMap,0x2|0x4|0x8,0,0,size,NULL)
		return [addr,hMap]

	def unmap(self,addr,hMap):
		kernel32.UnmapViewOfFile(addr)
		kernel32.CloseHandle(hMap)
		
class TriggerOut:
	def save(self,device,ioctl,case,inlen,outbuf,outlen,outfile):
		data = """from ctypes import *
from ctypes import wintypes
from win32con import NULL,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING
from win32file import INVALID_HANDLE_VALUE
from win32api import GetLastError;(kernel32,ntdll) = (windll.kernel32,windll.ntdll)
DeviceIoControl = windll.ntdll.ZwDeviceIoControlFile
(device,ioctl,case,inlen,outbuf,outlen) = (%s,%s,%s,%s,%s,%s)
handle = kernel32.CreateFileA("\\\\\\\\.\\\\%s",FILE_SHARE_WRITE|FILE_SHARE_READ,0,None,OPEN_EXISTING,0,None)
hMap = kernel32.CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,0x40,0,inlen,NULL)
addr = kernel32.MapViewOfFileEx(hMap,0x2|0x4|0x8,0,0,inlen,NULL)
kernel32.WriteProcessMemory(-1,addr,case,inlen,byref(c_int(0)))
print '[*] Device: '+str(device)+' Handle: '+str(handle)+' IOCTL: '+str(ioctl)+' Buffer(in): '+str(addr)+' Length: '+str(inlen)+' Buffer(out): '+str(outbuf)+' Length: '+str(outlen)
DeviceIoControl(handle,NULL,NULL,NULL,byref(c_ulong()),ioctl,hex(addr),inlen,outbuf,outlen)""" % ("\'"+device+"\'",ioctl,"\'"+str(case)+"\'",inlen,outbuf,outlen,device)
		fp = open(outfile,"w")
		fp.write(data)
		fp.close

class Handles:
	def createHandle(self,device):
		handle = kernel32.CreateFileA("\\\\.\\%s" % (device),FILE_SHARE_WRITE|FILE_SHARE_READ,0,None,OPEN_EXISTING,0,None)
		if (handle != -1):
			return handle
		else:
			print "[*] Couldnt open device"
			exit(1)
			
class Log:
	def add_entry(self,logFile,device,handle,ioctl,inbuf,inlen,outbuf,outlen):
		fp_log = open(logFile,'a+')
		fp_log.write("\n--\nDevice %s Handle: %s IOCTL: %s In Buffer: %s Length: %s Out Buffer: %s Length: %s" % (device,handle,ioctl,inbuf,inlen,outbuf,outlen))
		fp_log.close()

class Options:
	def get_args(self):
		print """
		-----------------------------------------------------
		| kfuzz (windows device driver fuzzer)              |
		| level@coresecurity.com                            |
		-----------------------------------------------------
		"""
		parser = OptionParser()
		parser.add_option("--device",dest="device",help="Device name (ex DVWD)")
		parser.add_option("--ioctl",dest="ioctl",type="int",help="IOCTL code to fuzz (ex 0x0022e007)")
		parser.add_option("--mutator",dest="mutator",help="Mutator to use (ex strings)")
		parser.add_option("--count",dest="count",type="int",help="Number of cases to execute")
		parser.add_option("--logfile",dest="logfile",help="File to log output too")
		parser.add_option("--zero-alloc",dest="logfile",help="Allocate 0x0-0x1000 (XP only)")
		parser.add_option("--list-mutators",action="store_true",help="Lists the available mutators")
		(o, a) = parser.parse_args()
		return o,a
	def list_mutators(self):
		return "Available mutators:\n\tlong strings (strings)\n\tspecial characters (special)\n\tformat strings (format)\n\tlarge and negative numbers (num)\n\tpredefined dwords (dwords)"
	
def main():
	opt,a = Options().get_args()
	if (opt.list_mutators is not None): 
		print Options().list_mutators()
		exit(0)
	try:
		if (opt.zalloc is not None):
			MemMgt().zalloc()
	except:
		print '[*] not mapping null page'
	handle = Handles().createHandle(opt.device)
	ioctl = hex(opt.ioctl)
	for i in xrange(0,opt.count):
		if (opt.mutator == "format"): case = mutate().format()
		if (opt.mutator == "num"): case = mutate().num()
		if (opt.mutator == "strings"): case = mutate().strings()
		if (opt.mutator == "special"): case = mutate().special()
		if (opt.mutator == "dword"): case = mutate().dword()
		inbuf,inlen,outbuf,outlen = build().return_addr(case,0),build().return_len(case),build().return_addr(case,1),build().return_len(case)
		TriggerOut().save(opt.device,ioctl,case,inlen,outbuf,outlen,"last_case.py")
		Popen("python last_case.py",stdout=PIPE,shell=False)
		try:
			if (build().memObj):
				MemMgt().unmap(memObj[0],memObj[1])
			if (build().memObj2):
				MemMgt().unmap(memObj2[0],memObj2[1])
		except: 
			continue
		del(inbuf,inlen,outbuf,outlen)
	exit(0)	
			
if __name__=="__main__":
	main()