/*Jiang Xiaotian 2023/1/8 Created*/
#include "type.h"

#ifndef EXT2_H
#define EXT2_H

#define BLOCKSIZE 1024
#define INODE_PER_GROUP 1712               //INODE_TABLE_BLOCK_SIZE * BLOCKSIZE / INODE_SIZE
#define INODE_TABLE_BLOCK_SIZE    214     //blocks
#define EXT2_MAX_PATH_LEN   255

#define EXT2_MAGIC  0xEF53

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;


void init_fs_ext2();

int ext2_create(const char *pathname);
int ext2_open(const char *pathname, int flags);
int ext2_close(int fd);
int ext2_write(int fd, const void *buf, int count);
int ext2_read(int fd, void *buf, int count);
int ext2_lseek(int fd, int offset, int whence);
int ext2_unlink(const char *pathname);
int ext2_mkdir(const char *pathname);
int ext2_getdents(int fd, struct linux_dirent *dirp, unsigned int count);

/*s_state values*/
#define     EXT2_VALID_FS                   1
#define     EXT2_ERROR_FS                   2  

/*s_error values*/
#define     EXT2_ERRORS_CONTINUE            1
#define     EXT2_ERRORS_RO                  2
#define     EXT2_ERRORS_PANIC               3
 
/*s_creator_os values*/
#define     EXT2_OS_LINUX                   0
#define     EXT2_OS_HURD                    1
#define     EXT2_OS_MASIX                   2
#define     EXT2_OS_FREEBSD                 3
#define     EXT2_OS_LITES                   4
#define     EXT2_OS_MINIOS                  5

/*s_rev_leve values*/
#define     EXT2_GOOD_OLD_REV               0
#define     EXT2_DYNAMIC_REV                1

#define     EXT2_DEF_RESUID                 0
#define     EXT2_DEF_RESGID                 0
/*s_first_ino values*/
#define     EXT2_GOOD_OLD_FIRST_INO         11

/*s_inode_size*/
#define     EXT2_GOOD_OLD_INODE_SIZE        128

struct ext2_superblock
{
    u32 s_inodes_count;
    u32 s_blocks_count;
    u32 s_r_blocks_count;
    u32 s_free_blocks_count;
    u32 s_free_inodes_count;
    u32 s_first_data_block;
    u32 s_log_block_size;
    u32 s_log_frag_size;
    u32 s_blocks_per_group;
    u32 s_frags_per_group;
    u32 s_inodes_per_group;
    u32 s_mtime;
    u32 s_wtime;
    u16 s_mnt_count;
    u16 s_max_mnt_count;
    u16 s_magic;
    u16 s_state;
    u16 s_errors;
    u16 s_minor_rev_level;
    u32 s_lastcheck;
    u32 s_checkinterval;
    u32 s_creator_os;                   
    u32 s_rev_level;                    //num of the ext2 revision
    u16 s_def_resuid;                   //user id
    u16 s_def_resgid;                   //group id
    /*EXT2_DYNAMIC_REV Specific*/
    u32 s_first_ino;                    //the first valid inode num
    u16 s_inode_size;
    u16 s_block_group_nr;
    u32 s_feature_compat;
    u32 s_feature_incompat;
    u32 s_feature_ro_compat;
    u8 s_uuid[16];
    char s_volume_name[16];
    char s_last_mounted[64];
    u32 s_algo_bitmap;
    /*Performance Hints*/
    u8 s_prealloc_blocks;
    u8 s_prealloc_dir_blocks;
    u16 align;      //unused, only for alignment
    /*Journaling Support*/
    u8 s_journal_uuid[16];
    u32 s_journal_inum;
    u32 s_journal_dev;
    u32 s_last_orphan;
    u32 s_hash_seed[4];
    u8 s_def_hash_version;
    u8 padding[3];
    u32 s_default_mount_options;
    u32 s_first_meta_bg;
    u8 Unused[760];
};

#define EXT2_BAD_INO            1
#define EXT2_ROOT_INO           2
#define EXT2_ACL_IDX_INO        3
#define EXT2_ACL_DATA_INO       4
#define EXT2_BOOT_LOADER_INO    5
#define EXT2_UNDEL_DIR_INO      6

struct bg_descriptor
{
    u32 bg_block_bitmap;
    u32 bg_inode_bitmap;
    u32 bg_inode_table;
    u16 bg_free_blocks_count;
    u16 bg_free_inodes_count;
    u16 bg_used_dirs_count;
    u16 bg_pad;
    u8 bg_reserved[12];
};

/*RESERVED INODES*/
#define EXT2_BAD_INO            1
#define EXT2_ROOT_INO           2
#define EXT2_ACL_IDX_INO        3
#define EXT2_ACL_DATA_INO       4
#define EXT2_BOOT_LOADER_INO    5
#define EXT2_UNDEL_DIR_INO      6

/*i_mode values*/
#define EXT2_S_IFSOCK           0XC000
#define EXT2_S_IFLNK            0XA000
#define EXT2_S_IFREG            0X8000
#define EXT2_S_IFBLK            0X6000
#define EXT2_S_IFDIR            0X4000
#define EXT2_S_IFIFO            0X1000
#define EXT2_S_ISUID            0X0800
#define EXT2_S_ISGID            0X0400
#define EXT2_S_ISVTX            0X0200
#define EXT2_S_IRUSR            0X0100
#define EXT2_S_IWUSR            0X0080
#define EXT2_S_IXUSR            0X0040
#define EXT2_S_IRGRP            0X0020
#define EXT2_S_IXGRP            0X0008
#define EXT2_S_IROTH            0X0004
#define EXT2_S_IWOTH            0X0002
#define EXT2_S_IXOTH            0X0001

struct ext2_inode
{
    u16 i_mode;
    u16 i_uid;
    u32 i_size;
    u32 i_atime;
    u32 i_ctime;
    u32 i_mtime;
    u32 i_dtime;
    u16 i_gid;
    u16 i_links_count;
    u32 i_blocks;
    u32 i_flags;
    u32 i_osd1;
    u32 i_block[15];
    u32 i_generation;
    u32 i_file_acl;
    u32 i_dir_acl;
    u32 i_faddr;
    u8 i_osd2[12];
};

struct ext2_dir_entry
{
    u32 inode;
    u16 rec_len;
    u16 name_len;       //revision 0 name_len is 16 bits len
    // u8 name_len;     used in revision 1
    // u8 file_type
    char name[0];
};

struct ext2_priv_data
{
    struct ext2_superblock sb;
    u32 bg_num;
    u32 blocksize;
    u32 first_bgd;
    u32 sectors_per_block;
    u32 inodes_per_blocks;
    u32 blocks_per_inode_table;
};

struct ext2_file_desc
{
    char fullpath[EXT2_MAX_PATH_LEN];
    u32 i_mode;
    u32 i_size;
    int i_dev;
    int i_cnt;
};

extern struct ext2_priv_data ext2_priv;

#endif