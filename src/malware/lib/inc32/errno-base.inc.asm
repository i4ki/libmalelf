;-----------------------------------------------------------------------------------------------
; Error numbers from linux-2.6.38.2/include/asm-generic/errno-base.h
; 18th April 2011
; note: raw syscalls (as opposed to the libc wrappers which return -1 and set errno)
;       generate negative return values in EAX for errors, so you should check if a syscalls
;       return value is signed, if it is use neg eax and then check the value against this list.
;------------------------------------------------------------------------------------------------
%define EPERM            1                   ;operation not permitted
%define ENOENT           2                   ;no such file or directory
%define ESRCH            3                   ;no such process
%define EINTR            4                   ;interrupted system call
%define EIO              5                   ;I/O error
%define ENXIO            6                   ;no such device or address
%define E2BIG            7                   ;argument list to long
%define ENOEXEC          8                   ;exec format error
%define EBADF            9                   ;bad file number
%define ECHILD           10                  ;no child processes
%define EAGAIN           11                  ;try again
%define ENOMEM           12                  ;out of memory
%define EACCES           13                  ;permission denied
%define EFAULT           14                  ;bad address
%define ENOTBLK          15                  ;block device rired
%define EBUSY            16                  ;device or resource busy
%define EEXIST           17                  ;file exists
%define EXDEV            18                  ;cross-device link
%define ENODEV           19                  ;no such device
%define ENOTDIR          20                  ;no such directory
%define EISDIR           21                  ;is a directory
%define EINVAL           22                  ;invalid argument
%define ENFILE           23                  ;file table overflow
%define EMFILE           24                  ;too many open files
%define ENOTTY           25                  ;not a typewriter
%define ETXTBSY          26                  ;text file busy
%define EFBIG            27                  ;file too large
%define ENOSPC           28                  ;no space left on device
%define ESPIPE           29                  ;illegal seek
%define EROFS            30                  ;read-only file system
%define EMLINK           31                  ;too many links
%define EPIPE            32                  ;broken pipe
%define EDOM             33                  ;math arg out of domain of func
%define ERANGE           34                  ;math result not representable
;--------------------------------------------------------------------------
; more error numbers from linux-2.6.38.2/include/asm-generic/errno.h
; 21st April 2011
;--------------------------------------------------------------------------
%define EDEADLCK         35                  ;resource deadlock would occur
%define ENAMETOOLONG     36                  ;file name too long
%define ENOLCK           37                  ;no record locks available
%define ENOSYS           38                  ;function not implemented
%define ENOTEMPTY        39                  ;directory not empty
%define ELOOP            40                  ;too many symbolic links encountered
%define EWOULDBLOCK      EAGAIN              ;operation would block
%define ENOMSG           42                  ;no message of desired type
%define EIDRM            43                  ;identifier removed
%define ECHRNG           44                  ;channel number out of range
%define EL2NSYNC         45                  ;level 2 not synchronized
%define EL3HLT           46                  ;level 3 halted
%define EL3RST           47                  ;level 3 reset
%define ELNRNG           48                  ;link number out of range
%define EUNATCH          49                  ;protocol driver not attached
%define ENOCSI           50                  ;no CSI structure available
%define EL2HLT           51                  ;level 2 halted
%define EBADE            52                  ;invalid exchange
%define EBADR            53                  ;invalid rest descriptor
%define EXFULL           54                  ;exchange full
%define ENOANO           55                  ;no anode
%define EBADROC          56                  ;invalid rest code
%define EBADSLT          57                  ;invalid slot
%define EDEADLOCK        EDEADLCK
%define EBFONT           59                  ;bad font file format
%define ENOSTR           60                  ;device not a stream
%define ENODATA          61                  ;no data available
%define ETIME            62                  ;timer expired
%define ENOSR            63                  ;out of streams resources
%define ENONET           64                  ;machine is not on the network
%define ENOPKG           65                  ;package not installed
%define EREMOTE          66                  ;object is remote
%define ENOLINK          67                  ;link has been severed
%define EADV             68                  ;advertise error
%define ESRMNT           69                  ;srmount error
%define ECOMM            70                  ;communication error on send
%define EPROTO           71                  ;protocol error
%define EMULTIHOP        72                  ;multihop attempted
%define EDOTDOT          73                  ;RFS specific error
%define EBADMSG          74                  ;not a data message
%define EOVERFLOW        75                  ;value too large for defined data
                                        ;type
%define ENOTUNIQ         76                  ;name not unique on network
%define EBADFD           77                  ;file descriptor in bad state
%define EREMCHG          78                  ;remote address changed
%define ELIBACC          79                  ;cannot access a needed shared lib
%define ELIBBAD          80                  ;accessing a corrupted shared lib
%define ELIBSCN          81                  ;.lib section in a.out corrupted
%define ELIBMAX          82                  ;attempting to link in too many shared
                                        ;libraries
%define ELIBEXEC         83                  ;cannot exec a shared lib directly
%define EILSEQ           84                  ;illegal byte sence
%define ERESTART         85                  ;interrupted system call should be
                                        ;restarted
%define ESTRPIPE         86                  ;streams pipe error
%define EUSERS           87                  ;too many users
%define ENOTSOCK         88                  ;socket operation on non-socket
%define EDESTADDRREQ     89                  ;destination address rired
%define EMSGSIZE         90                  ;message too long
%define EPROTOTYPE       91                  ;protocol wrong type for socket
%define ENOPROTOOPT      92                  ;protocol not available
%define EPROTONOSUPPORT  93                  ;protocol not supported
%define ESOCKTNOSUPPORT  94                  ;socket type not supported
%define EOPNOTSUPP       95                  ;operation not supported on transport
                                        ;endpoint
%define EPFNOSUPPORT     96                  ;protocol family not supported
%define EAFNOSUPPORT     97                  ;address family not supported by protocol
%define EADDRINUSE       98                  ;address already in use
%define EADDRNOTAVAIL    99                  ;cannot assign rested address
%define ENETDOWN         100                 ;network is down
%define ENETUNREACH      101                 ;network is unreachable
%define ENETRESET        102                 ;network dropped connection because of
                                        ;reset
%define ECONNABORTED     103                 ;software caused connection abort
%define ECONNRESET       104                 ;connection reset by peer
%define ENOBUFS          105                 ;no buffer space available
%define EISCONN          106                 ;transport endpoint is already connected
%define ENOTCONN         107                 ;transport endpoint is not connected
%define ESHUTDOWN        108                 ;cannot send after transport endpoint
                                        ;shutdown
%define ETOOMANYREFS     109                 ;too many references : cannot splice
%define ETIMEDOUT        110                 ;connection timed out
%define ECONNREFUSED     111                 ;connection refused
%define EHOSTDOWN        112                 ;host is down
%define EHOSTUNREACH     113                 ;no route to host
%define EALREADY         114                 ;operation already in progress
%define EINPROGRESS      115                 ;operation now in progress
%define ESTALE           116                 ;stale NFS file handle
%define EUCLEAN          117                 ;structure needs cleaning
%define ENOTNAM          118                 ;not a XENIX named type file
%define ENAVAIL          119                 ;no XENIX semaphores available
%define EISNAM           120                 ;is a named file type
%define EREMOTEIO        121                 ;remote I/O error
%define EDQUOT           122                 ;quota exceeded
%define ENOMEDIUM        123                 ;no medium found
%define EMEDIUMTYPE      124                 ;wrong medium type
%define ECANCELED        125                 ;operation canceled
%define ENOKEY           126                 ;rired key not available
%define EKEYEXPIRED      127                 ;key has expired
%define EKEYREVOKED      128                 ;key has been revoked
%define EKEYREJECTED     129                 ;key was rejected by service
;for robust mutexes
%define EOWNERDEAD       130                 ;owner died
%define ENOTRECOVERABLE  131                 ;state not recoverable
%define ERFKILL          132                 ;operation not possible due to RF-kill
;---------------------------------------------------------------------------------