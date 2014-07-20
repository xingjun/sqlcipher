#include <stdlib.h>
#include <string.h>
#include "sqlite3.h"
#include "sqlcipher.h"

#ifdef SQLCIPHER_VFS_DEBUG
#define SQLCIPHER_VFS_TRACE(X)  {printf X;fflush(stdout);}
#else
#define SQLCIPHER_VFS_TRACE(X)
#endif


static const char sqlcipherMagic[] = "SQLCipher Format 4.0.0.0.0.0.0.0";

/* these four sqlite3_file functions account for header allocation */
static int sqlcipherVfsRead(sqlite3_file*, void*, int iAmt, sqlite3_int64 iOfst);
static int sqlcipherVfsWrite(sqlite3_file*,const void*,int iAmt, sqlite3_int64);
static int sqlcipherVfsTruncate(sqlite3_file*, sqlite3_int64 size);
static int sqlcipherVfsFileSize(sqlite3_file*, sqlite3_int64 *pSize);

/* remaining sqlite3_file functions are transparent passthroughs */
static int sqlcipherVfsClose(sqlite3_file*);
static int sqlcipherVfsSync(sqlite3_file*, int flags);
static int sqlcipherVfsLock(sqlite3_file*, int);
static int sqlcipherVfsUnlock(sqlite3_file*, int);
static int sqlcipherVfsCheckReservedLock(sqlite3_file*, int *);
static int sqlcipherVfsFileControl(sqlite3_file*, int op, void *pArg);
static int sqlcipherVfsSectorSize(sqlite3_file*);
static int sqlcipherVfsDeviceCharacteristics(sqlite3_file*);
static int sqlcipherVfsShmLock(sqlite3_file*,int,int,int);
static int sqlcipherVfsShmMap(sqlite3_file*,int,int,int, void volatile **);
static void sqlcipherVfsShmBarrier(sqlite3_file*);
static int sqlcipherVfsShmUnmap(sqlite3_file*,int);

static int sqlcipherVfsOpen(sqlite3_vfs*, const char *, sqlite3_file*, int , int *);

static int sqlcipherVfsRead(
  sqlite3_file *pFile, 
  void *zBuf, 
  int iAmt, 
  sqlite_int64 iOfst
){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xRead(p->pReal, zBuf, iAmt, iOfst + p->reserve_sz);
}

static int sqlcipherVfsWrite(
  sqlite3_file *pFile, 
  const void *zBuf, 
  int iAmt, 
  sqlite_int64 iOfst
){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  if(p->reserve_sz == 32 && iOfst == 0) {
    // write the header of the file when offset 0 is written 
    if(p->pReal->pMethods->xWrite(p->pReal, sqlcipherMagic, 32, 0) == SQLITE_OK) {
      SQLCIPHER_VFS_TRACE(("wrote file header\n"));
    } else {
      SQLCIPHER_VFS_TRACE(("file header write failed!\n"));
    }
  }
  return p->pReal->pMethods->xWrite(p->pReal, zBuf, iAmt, iOfst + p->reserve_sz);
}

static int sqlcipherVfsTruncate(sqlite3_file *pFile, sqlite_int64 size){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xTruncate(p->pReal, size + p->reserve_sz);
}

static int sqlcipherVfsFileSize(sqlite3_file *pFile, sqlite_int64 *pSize){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  int rc;
  sqlite_int64 rSize;
  rc = p->pReal->pMethods->xFileSize(p->pReal, &rSize);
  *pSize = rSize - p->reserve_sz;
  return rc;
}

static int sqlcipherVfsClose(sqlite3_file *pFile){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xClose(p->pReal);
}

static int sqlcipherVfsSync(sqlite3_file *pFile, int flags){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xSync(p->pReal, flags);
}

static int sqlcipherVfsLock(sqlite3_file *pFile, int eLock){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xLock(p->pReal, eLock);
}

static int sqlcipherVfsUnlock(sqlite3_file *pFile, int eLock){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xUnlock(p->pReal, eLock);
}

static int sqlcipherVfsCheckReservedLock(sqlite3_file *pFile, int *pResOut){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xCheckReservedLock(p->pReal, pResOut);
}

static int sqlcipherVfsFileControl(sqlite3_file *pFile, int op, void *pArg){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xFileControl(p->pReal, op, pArg);
}

static int sqlcipherVfsSectorSize(sqlite3_file *pFile){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xSectorSize(p->pReal);
}

static int sqlcipherVfsDeviceCharacteristics(sqlite3_file *pFile){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xDeviceCharacteristics(p->pReal);
}

static int sqlcipherVfsShmLock(sqlite3_file *pFile, int ofst, int n, int flags){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xShmLock(p->pReal, ofst, n, flags);
}

static int sqlcipherVfsShmMap(
  sqlite3_file *pFile,
  int iRegion,
  int szRegion,
  int isWrite,
  void volatile **pp
){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xShmMap(p->pReal, iRegion, szRegion, isWrite, pp);
}

static void sqlcipherVfsShmBarrier(sqlite3_file *pFile){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  p->pReal->pMethods->xShmBarrier(p->pReal);
}

static int sqlcipherVfsShmUnmap(sqlite3_file *pFile, int delFlag){
  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  return p->pReal->pMethods->xShmUnmap(p->pReal, delFlag);
}


static int sqlcipherVfsOpen(
  sqlite3_vfs *pVfs,
  const char *zName,
  sqlite3_file *pFile,
  int flags,
  int *pOutFlags
){
  int rc;
  unsigned char magic[32];
  sqlite_int64 fsize;

  SQLCIPHER_VFS_TRACE(("sqlcipherVfsOpen\n"));

  sqlcipherVfs_file *p = (sqlcipherVfs_file *)pFile;
  sqlcipherVfs_info *pInfo = (sqlcipherVfs_info*)pVfs->pAppData;
  sqlite3_vfs *pRoot = pInfo->pRootVfs;
  p->pInfo = pInfo;
  p->pReal = (sqlite3_file *)&p[1];
  rc = pRoot->xOpen(pRoot, zName, p->pReal, flags, pOutFlags);


  if(p->pReal->pMethods->xRead(p->pReal, magic, 32, 0) == SQLITE_OK) {
    SQLCIPHER_VFS_TRACE(("read 32 bytes from file header\n"));
    // file exists and read first 32 bytes, compare to magic;
    if(memcmp(magic, sqlcipherMagic, 32) == 0) {
      SQLCIPHER_VFS_TRACE(("file header magic matches setting reserve size to 32\n"));
      p->reserve_sz = 32;
    } else {
      SQLCIPHER_VFS_TRACE(("file header does not match magic setting reserve size to 0\n"));
      p->reserve_sz = 0;
    }
  } else if (p->pReal->pMethods->xFileSize(p->pReal, &fsize) == SQLITE_OK && fsize == 0) {
    SQLCIPHER_VFS_TRACE(("file size is 0, database doesnt exist, setting reserve size\n"));
    p->reserve_sz = 32;
  } else {
    SQLCIPHER_VFS_TRACE(("unknown issue\n"));
  }

  /* setup some stuff for sqlcipher */

  if( p->pReal->pMethods ){
    sqlite3_io_methods *pNew = sqlite3_malloc( sizeof(*pNew) );
    const sqlite3_io_methods *pSub = p->pReal->pMethods;
    memset(pNew, 0, sizeof(*pNew));

    pNew->iVersion = pSub->iVersion;
    pNew->xClose = sqlcipherVfsClose;
    pNew->xRead = sqlcipherVfsRead; /* modified to account for header */
    pNew->xWrite = sqlcipherVfsWrite; /* modified to account for header */
    pNew->xTruncate = sqlcipherVfsTruncate; /* modified to account for header */
    pNew->xSync = sqlcipherVfsSync;
    pNew->xFileSize = sqlcipherVfsFileSize; /* modified to account for header */
    pNew->xLock = sqlcipherVfsLock;
    pNew->xUnlock = sqlcipherVfsUnlock;
    pNew->xCheckReservedLock = sqlcipherVfsCheckReservedLock;
    pNew->xFileControl = sqlcipherVfsFileControl;
    pNew->xSectorSize = sqlcipherVfsSectorSize;
    pNew->xDeviceCharacteristics = sqlcipherVfsDeviceCharacteristics;
    if( pNew->iVersion>=2 ){
      pNew->xShmMap = pSub->xShmMap ? sqlcipherVfsShmMap : 0;
      pNew->xShmLock = pSub->xShmLock ? sqlcipherVfsShmLock : 0;
      pNew->xShmBarrier = pSub->xShmBarrier ? sqlcipherVfsShmBarrier : 0;
      pNew->xShmUnmap = pSub->xShmUnmap ? sqlcipherVfsShmUnmap : 0;
    }

    pFile->pMethods = pNew;
  }
  return rc;
}

/*
** Register SQLCipher VFS shim
**
** Return SQLITE_OK on success.  
**
** SQLITE_NOMEM is returned in the case of a memory allocation error.
** SQLITE_NOTFOUND is returned if zOldVfsName does not exist.
*/
int sqlcipherVfs_register(
   const char *zOldVfsName          /* Name of the underlying VFS */
){
  sqlite3_vfs *pNew;
  sqlite3_vfs *pRoot;
  sqlcipherVfs_info *pInfo;
  const char *newVfsName = "sqlcipher";
  int nName;
  int nByte;

  SQLCIPHER_VFS_TRACE(("sqlcipherVfs_register\n"));

  pNew = sqlite3_vfs_find(newVfsName);
  if( pNew == NULL) {
    SQLCIPHER_VFS_TRACE(("sqlcipher has not yet been registered\n"));
    pRoot = sqlite3_vfs_find(zOldVfsName);
    if( pRoot==0 ) return SQLITE_NOTFOUND;
    nName = strlen(newVfsName);
    nByte = sizeof(*pNew) + sizeof(*pInfo) + nName + 1;
    pNew = sqlite3_malloc( nByte );
    if( pNew==0 ) return SQLITE_NOMEM;
    memset(pNew, 0, nByte);
    pInfo = (sqlcipherVfs_info*)&pNew[1];
  
    pNew->szOsFile = pRoot->szOsFile + sizeof(sqlcipherVfs_file);
    pNew->zName = (char*)&pInfo[1];
    memcpy((char*)&pInfo[1], newVfsName, nName+1);
    pNew->pAppData = pInfo;
  
    /* override xOpen so we use our own custom 
     * sqlcipherVfs_file implementation */
    pNew->xOpen = sqlcipherVfsOpen;
  
    /* all other VFS functions will point directly back to root */
    pNew->iVersion = pRoot->iVersion;
    pNew->mxPathname = pRoot->mxPathname;
    pNew->xDelete = pRoot->xDelete;
    pNew->xFullPathname = pRoot->xFullPathname;
    pNew->xAccess = pRoot->xAccess;
    pNew->xDlOpen = pRoot->xDlOpen;
    pNew->xDlError = pRoot->xDlError;
    pNew->xDlSym = pRoot->xDlSym;
    pNew->xDlClose = pRoot->xDlClose;
    pNew->xRandomness = pRoot->xRandomness;
    pNew->xSleep = pRoot->xSleep;
    pNew->xCurrentTime = pRoot->xCurrentTime;
    pNew->xGetLastError = pRoot->xGetLastError;
  
    if( pNew->iVersion>=2 ){
      pNew->xCurrentTimeInt64 = pRoot->xCurrentTimeInt64;
  
      if( pNew->iVersion>=3 ){
        pNew->xSetSystemCall = pRoot->xSetSystemCall;
        pNew->xGetSystemCall = pRoot->xGetSystemCall;
        pNew->xNextSystemCall = pRoot->xNextSystemCall;
      }
    }
  
    pInfo->pRootVfs = pRoot;
    pInfo->pSqlcipherVfs = pNew;
  } else {
    // if sqlcipher has already been registered, just ensure it's default
    SQLCIPHER_VFS_TRACE(("sqlcipher VFS has already been registered, skipping registration\n"));
  }

  return sqlite3_vfs_register(pNew, 1);
}
