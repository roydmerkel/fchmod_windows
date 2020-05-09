#ifndef FCHMOD_H
#define FCHMOD_H

#ifndef S_ISUID
#define S_ISUID 04000
#endif /* S_ISUID */

#ifndef S_ISGID
#define S_ISGID 02000
#endif /* S_ISGID */

int fchmod(int fd, int mode);

#endif
