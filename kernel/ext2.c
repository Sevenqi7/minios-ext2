/*Jiang Xiaotian 2023/1/8 Create*/
#include "ext2.h"
#include "type.h"
#include "const.h"
#include "protect.h"
#include "string.h"
#include "proc.h"
#include "tty.h"
#include "console.h"
#include "assert.h"
#include "global.h"
#include "proto.h"
#include "vfs.h"
#include "fs_const.h"
#include "hd.h"
#include "fs.h"
#include "fs_misc.h"
#include "string.h"
#include "stdio.h"

#define SINGLY_LINKED_MAX (ext2_priv.blocksize / 4 + 12)
#define DOUBLY_LINKED_MAX (ext2_priv.blocksize / 4 * (SINGLY_LINKED_MAX - 12) + SINGLY_LINKED_MAX)
#define TRIPLY_LINKED_MAX (ext2_priv.blocksize / 4 * (DOUBLY_LINKED_MAX - SINGLY_LINKED_MAX) +DOUBLY_LINKED_MAX)

extern struct file_desc f_desc_table[NR_FILE_DESC];	

static struct ext2_file_desc ext2_file_desc_table[NR_INODE];	
struct ext2_priv_data ext2_priv;
static u32 ext2_dev;

static int rw_sector(int io_type, int dev, u64 pos, int bytes, int proc_nr, void* buf);
static int is_A_Power_Of_B(int a, int b);
static int split_path(char *fullpath);

static void ext2_read_block(u8 *buf, u32 block, u32 dev, struct ext2_priv_data *priv);
static void ext2_write_block(u8 *buf, u32 block, u32 dev, struct ext2_priv_data *priv);
static void ext2_read_inode(struct ext2_inode *inode_buf, u32 inode, u32 dev, struct ext2_priv_data *priv);
static void ext2_write_inode(struct ext2_inode *inode_buf, u32 inode, u32 dev, struct ext2_priv_data *priv);
static void ext2_write_all_superblock(u8 *buf, u32 dev, struct ext2_priv_data *priv);
static void ext2_write_all_bgdt(u8 *buf, u32 dev, struct ext2_priv_data *priv);
static int ext2_read_singly_linked(u8 *buf, u32 block, u32 start_block, u32 count, u32 dev, struct ext2_priv_data *priv);
static int ext2_write_singly_linked(const char *buf, u32 block, u32 inode, struct ext2_inode *inode_buf, 
                                u32 start_block, u32 count, u32 dev, struct ext2_priv_data *priv);
static int ext2_read_doubly_linked(u8 *buf, u32 block, u32 doubly_offset, u32 singly_offset, u32 count, u32 dev, struct ext2_priv_data *priv);
static int ext2_write_doubly_linked(const char *buf, u32 block, u32 inode, struct ext2_inode *inode_buf, 
                                u32 doubly_offset, u32 singly_offset, u32 count, u32 dev, struct ext2_priv_data *priv);
static int ext2_read_triply_linked(u8 *buf, u32 block, u32 triply_offset, u32 doubly_offset, u32 singly_offset, u32 count, u32 dev, struct ext2_priv_data *priv);
static int ext2_write_triply_linked(u8 *buf, u32 block, u32 inode, struct ext2_inode *inode_buf, u32 triply_offset, 
                            u32 doubly_offset, u32 singly_offset, u32 count, u32 dev, struct ext2_priv_data *priv);

static void ext2_set_block(u32 block, u32 dev, struct ext2_priv_data *priv);
static void ext2_free_block(u32 block, u32 dev, struct ext2_priv_data *priv);
static int ext2_alloc_block(u32 inode_id, struct ext2_inode *inode_buf, u32 dev, struct ext2_priv_data *priv);
static int ext2_alloc_inode(const char *fullpath, u32 dev, struct ext2_priv_data *priv);
static void ext2_free_inode(u32 inode_id, u32 dev, struct ext2_priv_data *priv);
static int ext2_search_file_in_directory(char *filename, struct ext2_dir_entry *dir_start, u32 dev, struct ext2_priv_data *priv);
static int ext2_find_file_inode(const char *fullpath, struct ext2_inode *inode, u32 dev, struct ext2_priv_data *priv);
static void ext2_new_entry(u32 dir_inode, struct ext2_dir_entry *new_entry, u32 dev, struct ext2_priv_data *priv);

static int ext2_create_dir(const char *fullpath, char *dirname, u32 dev, struct ext2_priv_data *priv);
static int ext2_create_file(const char *fullpath, char *filename, u32 dev, struct ext2_priv_data *priv);
static int ext2_open_file(MESSAGE *fs_msg, u32 dev, struct ext2_priv_data *priv);
static int ext2_write_file(const char *fullpath, const char *buf, int begin, int len, u32 dev, struct ext2_priv_data *priv);
static int ext2_read_file(const char *fullpath, char *buf, int begin, int len, u32 dev, struct ext2_priv_data *priv); 
static int ext2_unlink_file(const char *fullpath, u32 dev, struct ext2_priv_data *priv);
static int ext2_do_lseek(MESSAGE *fs_msg);
static int ext2_do_getdents(const char *fullpath, struct linux_dirent *dirp, unsigned int count, u32 dev, struct ext2_priv_data *priv);


// u8 *ext2_fs_buf;
void ext2_create_root_dir(u32 dev, struct ext2_priv_data *priv);
int get_fs_dev(int drive, int fs_type);
void mkfs_ext2(int dev);

char meg[4096] = "Four score and seven years ago our fathers brought forth ,on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.\nNow we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that nation might live. It is altogether fitting and proper that we should do this.\nBut, in a larger sense, we can not dedicate -- we can not consecrate -- we can not hallow -- this ground. The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us -- that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion -- that we here highly resolve that these dead shall not have died in vain -- that this nation, under God, shall have a new birth of freedom -- and that government of the people, by the people, for the people, shall not perish from the earth.";

void init_fs_ext2()
{
    kprintf("Initializing ext2 file system...  \n");
    ext2_dev = get_fs_dev(PRIMARY_MASTER, EXT2_TYPE);
    // ext2_dev = 802;
    kprintf("ext2 devnum:%d\n", ext2_dev);
    

    struct ext2_superblock *sb_buf = (struct ext2_superblock *)K_PHY2LIN(sys_kmalloc(1024));
    RD_SECT(ext2_dev, 2, sb_buf);
    RD_SECT(ext2_dev, 3, sb_buf+512);
    if(sb_buf->s_magic != 0xEF53 || sb_buf->s_state != EXT2_VALID_FS)
    {
        mkfs_ext2(ext2_dev);
        // ext2_create_file("/", "test.txt", ext2_dev, &ext2_priv);
        // ext2_write_file("/test.txt", meg, 0, 2048, ext2_dev, &ext2_priv);
        RD_SECT(ext2_dev, 2, sb_buf);
        RD_SECT(ext2_dev, 3, sb_buf+512);
    }
    ext2_priv.bg_num = sb_buf->s_blocks_count / sb_buf->s_blocks_per_group + (sb_buf->s_blocks_count % sb_buf->s_blocks_per_group > 0);
    ext2_priv.blocksize = 1024 << sb_buf->s_log_block_size;
    ext2_priv.sb = *sb_buf;
    ext2_priv.first_bgd = sb_buf->s_first_data_block + 1;
    ext2_priv.inodes_per_blocks = ext2_priv.blocksize / sb_buf->s_inode_size;
    ext2_priv.sectors_per_block = ext2_priv.blocksize / SECTOR_SIZE;
    ext2_priv.blocks_per_inode_table = sb_buf->s_inodes_per_group * sb_buf->s_inode_size / ext2_priv.blocksize;
    kprintf("blocks count: %d  ", sb_buf->s_blocks_count);
    kprintf("block group num: %d  ", ext2_priv.bg_num);
    kprintf("blocks per group: %d  \n", sb_buf->s_blocks_per_group);
    kprintf("block size: %d\n", ext2_priv.blocksize);

    // kprintf("\n 1:%d 2:%d 3:%d\n", SINGLY_LINKED_MAX, DOUBLY_LINKED_MAX, TRIPLY_LINKED_MAX);
    sys_free2(sb_buf, sizeof(struct ext2_superblock));
    // ext2_unlink_file("/a/test.txt", ext2_dev, &ext2_priv);
}

void mkfs_ext2(int dev)
{
    MESSAGE driver_msg;
    struct part_info geo;
    char ext2_fs_buf[BLOCKSIZE];
    driver_msg.type = DEV_IOCTL;
    driver_msg.DEVICE = MINOR(dev);
    driver_msg.REQUEST = DIOCTL_GET_GEO;
    driver_msg.BUF = &geo;
    driver_msg.PROC_NR = proc2pid(p_proc_current);
    hd_ioctl(&driver_msg);
    kprintf("dev size: 0x%x sectors\n", geo.size);

    /***********************/
    /*     super block     */
    /***********************/
    struct ext2_superblock sb;
    memset(&sb, 0, sizeof(sb));
    sb.s_blocks_per_group = BLOCKSIZE * 8;
    sb.s_frags_per_group = BLOCKSIZE * 8;
    sb.s_inodes_per_group = INODE_PER_GROUP;
    sb.s_blocks_count = SECTOR_SIZE * geo.size / BLOCKSIZE + (((SECTOR_SIZE * geo.size) % BLOCKSIZE ) ? 1 : 0);
    sb.s_block_group_nr = sb.s_blocks_count / sb.s_blocks_per_group ;
    if(sb.s_blocks_count % sb.s_blocks_per_group)
        sb.s_block_group_nr++;
    sb.s_inodes_count = sb.s_block_group_nr * sb.s_inodes_per_group;
    sb.s_r_blocks_count = 0;
    sb.s_first_data_block = (BLOCKSIZE == 1024) ? 1 : 0;
    sb.s_log_block_size = (BLOCKSIZE / 1024) -1;
    sb.s_mtime = 0;
    sb.s_wtime = 0;
    sb.s_mnt_count = 0;
    sb.s_max_mnt_count = -1;
    sb.s_magic = 0xEF53;   
    sb.s_state = EXT2_VALID_FS;
    sb.s_errors = EXT2_ERRORS_CONTINUE;
    sb.s_minor_rev_level = 0;        //unused
    sb.s_lastcheck = 0;
    sb.s_checkinterval = 0;          //unused
    sb.s_creator_os = EXT2_OS_LINUX;
    sb.s_rev_level = EXT2_GOOD_OLD_REV;
    sb.s_def_resuid = EXT2_DEF_RESUID;
    sb.s_def_resgid = EXT2_DEF_RESGID;
    sb.s_first_ino = EXT2_GOOD_OLD_FIRST_INO; 
    sb.s_inode_size = EXT2_GOOD_OLD_INODE_SIZE;

    sb.s_feature_compat = 0;    //unused
    sb.s_feature_incompat = 0;  //unused
    sb.s_feature_ro_compat = 0; //unused

    char uuid[16] = {'E','X','T','2','T','E','S','T'};
    char volume_name[16] = {'E','X','T','2'};
    memcpy(&sb.s_uuid, uuid, sizeof(uuid));
    memcpy(&sb.s_volume_name, volume_name, sizeof(volume_name));
    memset(&sb.s_last_mounted, 0, sizeof(sb.s_last_mounted));
    sb.s_algo_bitmap = 0;        //unused
    sb.s_prealloc_blocks = 0;    //unused
    sb.s_prealloc_dir_blocks = 0;//unused

    /*********SUPER BLOCK FINISH*********/

    /**************************************/
    /*    BLOCK GROUP DESCRIPTOR TABLE    */
    /**************************************/
    struct bg_descriptor bg_desc[sb.s_block_group_nr];
    memset(bg_desc, 0, sizeof(bg_desc));
    sb.s_free_blocks_count = sb.s_free_inodes_count = 0;
    u32 block_left = sb.s_blocks_count - 1;     //boot
    for(int i=0;i<sb.s_block_group_nr;i++)
    {
        bg_desc[i].bg_block_bitmap = i * sb.s_blocks_per_group + 3;
        bg_desc[i].bg_inode_bitmap = i * sb.s_blocks_per_group + 4;
        bg_desc[i].bg_inode_table =  i * sb.s_blocks_per_group + 5;
        if(block_left > sb.s_blocks_per_group)
        {   
            bg_desc[i].bg_free_blocks_count = sb.s_blocks_per_group - 4     //super block, GDT, two bitmaps 
                                               - INODE_TABLE_BLOCK_SIZE;                       //inode table
            block_left -= sb.s_blocks_per_group;
        }
        else if(block_left < 4 + INODE_TABLE_BLOCK_SIZE)
        {
            bg_desc[i].bg_free_blocks_count = 0;
        }
        else
            bg_desc[i].bg_free_blocks_count = block_left - 4 - INODE_TABLE_BLOCK_SIZE;
        bg_desc[i].bg_free_inodes_count = (i == 0) ? sb.s_inodes_per_group - sb.s_first_ino + 1:
                                                     sb.s_inodes_per_group;
        sb.s_free_blocks_count += bg_desc[i].bg_free_blocks_count;
        sb.s_free_inodes_count += bg_desc[i].bg_free_inodes_count;
    }

    memcpy(ext2_fs_buf, &sb, 1024);
    kprintf("free_blocks_count: %d\n", sb.s_free_blocks_count);
    for(int i=1;i<sb.s_blocks_count;i+=sb.s_blocks_per_group)
    {
        WR_SECT(dev, i * 2, ext2_fs_buf);          //superblock always start at 1024th bytes
        WR_SECT(dev, i * 2 + 1, &ext2_fs_buf[512]);
    }

    for(int i=2;i<sb.s_blocks_count;i+=sb.s_blocks_per_group)
    {
        WR_SECT(dev, i * 2, bg_desc);
        WR_SECT(dev, i * 2 + 1, &((u8 *)bg_desc)[512]);
    }

    /*********    GDT FINISH    *********/

    struct ext2_inode inode_table[sb.s_inodes_per_group];
    u8 bitmap[BLOCKSIZE];
    memset(bitmap, 0, sizeof(bitmap));

    /************    block_bitmap  ************/
    int i, j;
    block_left = sb.s_blocks_count - 1;                     //block 0(boot) is not in block group
    for(i=0;i<(INODE_TABLE_BLOCK_SIZE + 4) / 8;i++)         //superblock, GDT, two bitmaps 
        bitmap[i] = (u8) 0xff;
    for(j=0;j<(INODE_TABLE_BLOCK_SIZE + 4) % 8;j++)
        bitmap[i] = (bitmap[i] << 1) + 1;

    for(i=3;i<sb.s_blocks_count;i+=sb.s_blocks_per_group)   //one block = two sector
    {   
        if(block_left >= sb.s_blocks_per_group)
        {
            WR_SECT(dev, i * 2, bitmap);
            WR_SECT(dev, i * 2 + 1, &bitmap[512]);
        }
        else
        {
            bitmap[block_left / 8] = 0xff << (block_left % 8);
            for(j=block_left / 8 + 1;j<BLOCKSIZE;j++)
                bitmap[j] = 0xff;
            WR_SECT(dev, i * 2, bitmap);
            WR_SECT(dev, i * 2 + 1, &bitmap[512]);
        }
        block_left -= sb.s_blocks_per_group;
    }

    /*********   block_bitmap finish  *********/

    memset(bitmap, 0, sizeof(bitmap));

    /*         inodes_bitmap        */

    bitmap[0] = (u8) 0xff;                                   //first 10 nodes are reserved
    bitmap[1] = (u8) 0x03;
    for(i=0;i<sb.s_inodes_per_group % 8;i++)
        bitmap[sb.s_inodes_per_group / 8] |= 1<<i;
    for(i=sb.s_inodes_per_group / 8 + 1;i<BLOCKSIZE;i++)
        bitmap[i] = (u8) 0xff;
    WR_SECT(dev, 4 * 2, bitmap);
    WR_SECT(dev, 4 *2 + 1, &bitmap[512]);
    bitmap[0] = bitmap[1] = 0;
    for(i=4+sb.s_blocks_per_group;i<sb.s_blocks_count;i += sb.s_blocks_per_group)
    {
        WR_SECT(dev, i * 2, bitmap);
        WR_SECT(dev, i * 2 + 1, &bitmap[512]);
    }


    struct ext2_priv_data *priv;
    priv = &ext2_priv;
    priv->sb = sb;
    priv->bg_num = sb.s_block_group_nr;
    priv->blocksize = BLOCKSIZE;
    priv->first_bgd = 2;
    priv->inodes_per_blocks = BLOCKSIZE / sb.s_inode_size;
    priv->sectors_per_block = BLOCKSIZE / SECTOR_SIZE;
    priv->blocks_per_inode_table = INODE_TABLE_BLOCK_SIZE;


    ext2_create_root_dir(dev, priv);

}

static int rw_sector(int io_type, int dev, u64 pos, int bytes, int proc_nr, void* buf)
{
	MESSAGE driver_msg;
	
	driver_msg.type		= io_type;
	driver_msg.DEVICE	= MINOR(dev);
	driver_msg.POSITION	= pos;
	driver_msg.CNT		= bytes;	/// hu is: 512
	driver_msg.PROC_NR	= proc_nr;
	driver_msg.BUF		= buf;

	hd_rdwt(&driver_msg);
	return 0;
}

static int is_A_Power_Of_B(int a, int b)
{
    if(a<1 || a<b)
        return 0;
    else
    {
        while(a % b == 0)
            a /= b;
        return (a == 1);
    }
}

//split the path with '/', and return number of pieces
static int split_path(char *fullpath)
{
    int ret = 0;
    if(fullpath[strlen(fullpath)-1] == '/')
        ret--;
    for(int i=0;fullpath[i];i++)
    {
        if(fullpath[i] == '/')
            fullpath[i] = '\0', ret++;
    }
    return ret;
}

int ext2_create(const char *pathname)
{
    int fd = -1;
    char path_buf[EXT2_MAX_PATH_LEN];
    memcpy(path_buf, pathname, strlen(pathname)+1);
    char *filename, *path = path_buf;
    int index, offset;
    for(index=strlen(path_buf)-1;path_buf[index]!='/';index--);
    if(index != 0)
        path_buf[index] = '\0';
    else
        path = "/";
    filename = &path_buf[index]+1;
    int file_inode = ext2_create_file((const char *)path, filename, ext2_dev, &ext2_priv);
    if(!file_inode)
        return -1;
    int i;
    for(i=0;i<NR_INODE;i++)
    {
        if(ext2_file_desc_table[i].i_cnt == 0)
        {
            ext2_file_desc_table[i].i_cnt++;
            ext2_file_desc_table[i].i_dev = MINOR(ext2_dev);
            ext2_file_desc_table[i].i_mode = O_RDWR;
            ext2_file_desc_table[i].i_size = 0;
            memcpy(ext2_file_desc_table[i].fullpath, pathname, strlen(pathname)+1);
            break;
        }
    }
    int fd_index = i;
    for(i=0;i<NR_FILES;i++)
    {
        if(p_proc_current->task.filp[i] == 0)
        {
            fd = i;
            break;
        }
    }

    for(i=0;i<NR_FILE_DESC;i++)
        if(f_desc_table[i].flag == 0)
            break;

    if(fd != -1)
    {
        p_proc_current->task.filp[fd] = &f_desc_table[i];
        f_desc_table[i].flag = 1;
        f_desc_table[i].fd_node.fd_ext2_inode = &ext2_file_desc_table[fd_index];
        f_desc_table[i].fd_pos = 0;
        f_desc_table[i].fd_mode = O_RDWR;
    }
    
    return fd;
}

int ext2_open(const char *pathname, int flags)
{
    MESSAGE fs_msg;

    fs_msg.type = OPEN;
    fs_msg.PATHNAME = (void *)pathname;
    fs_msg.FLAGS = flags;
    fs_msg.NAME_LEN = strlen(pathname);
    fs_msg.source = proc2pid(p_proc_current);

    return ext2_open_file(&fs_msg, ext2_dev, &ext2_priv);
}


int ext2_close(int fd)
{
    p_proc_current->task.filp[fd]->fd_node.fd_ext2_inode->i_cnt--;
    p_proc_current->task.filp[fd]->fd_node.fd_ext2_inode = 0;
    p_proc_current->task.filp[fd]->flag = 0;
    p_proc_current->task.filp[fd] = 0;
    return 0;
}

int ext2_write(int fd, const void *buf, int count)
{
    char *fullpath = p_proc_current->task.filp[fd]->fd_node.fd_ext2_inode->fullpath;
    int pos = p_proc_current->task.filp[fd]->fd_pos;
    int byte_num = ext2_write_file((const char *)fullpath, buf, pos, count, ext2_dev, &ext2_priv);
    p_proc_current->task.filp[fd]->fd_pos += byte_num;
    return byte_num;
}

int ext2_lseek(int fd, int offset, int whence)
{
	MESSAGE fs_msg;
	
	fs_msg.FD = fd;
	fs_msg.OFFSET = offset;
	fs_msg.WHENCE = whence;

	return ext2_do_lseek(&fs_msg);
}

int ext2_unlink(const char *pathname)
{
    return ext2_unlink_file(pathname, ext2_dev, &ext2_priv);
}

int ext2_read(int fd, void *buf, int count)
{
    char *fullpath = p_proc_current->task.filp[fd]->fd_node.fd_ext2_inode->fullpath;
    int pos = p_proc_current->task.filp[fd]->fd_pos;
    int byte_num = ext2_read_file((const char *)fullpath, buf, pos, count, ext2_dev, &ext2_priv);
    p_proc_current->task.filp[fd]->fd_pos += byte_num;
    return byte_num;
}

int ext2_mkdir(const char *pathname)
{
    int i;
    char fullpath[strlen(pathname)+1];
    memcpy(fullpath, pathname, strlen(pathname));
    fullpath[strlen(pathname)+1] = '\0';
    for(i=strlen(fullpath)-1;fullpath[i]!='/';i--);
    char *dirname, *path, root = '/';
    if(i != 0)
        fullpath[i] = '\0';
    else
        path = "/";
    dirname = &fullpath[i+1];
    return ext2_create_dir(path, dirname, ext2_dev, &ext2_priv);
}

int ext2_getdents(int fd, struct linux_dirent *dirp, unsigned int count)
{
    char *fullpath = p_proc_current->task.filp[fd]->fd_node.fd_ext2_inode->fullpath;
    return ext2_do_getdents(fullpath, dirp, count, ext2_dev, &ext2_priv);
}

static void ext2_read_block(u8 *buf, u32 block, u32 dev, struct ext2_priv_data *priv)
{
    int sectors_per_block = priv->sectors_per_block;
    if(!sectors_per_block) sectors_per_block = 1;
    for(int i=0;i<sectors_per_block;i++)
        RD_SECT(dev, sectors_per_block * block + i, buf + i * SECTOR_SIZE);
}

static void ext2_write_block(u8 *buf, u32 block, u32 dev, struct ext2_priv_data *priv)
{
    int sectors_per_block = priv->sectors_per_block;
    if(!sectors_per_block) sectors_per_block = 1;
    for(int i=0;i<sectors_per_block;i++)
        WR_SECT(dev, sectors_per_block * block + i, buf + i * SECTOR_SIZE);

}

static void ext2_read_inode(struct ext2_inode *inode_buf, u32 inode, u32 dev, struct ext2_priv_data *priv)
{
    int bg = (inode-1) / priv->sb.s_inodes_per_group;
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor *bgd = (struct bg_descriptor *)block_buf + bg;
    int index = (inode - 1) % priv->sb.s_inodes_per_group;
    int block = (index * sizeof(struct ext2_inode)) / priv->blocksize;
    ext2_read_block(block_buf, bgd->bg_inode_table + block, dev, priv);
    struct ext2_inode *inode_tmp = (struct ext2_inode *)block_buf;
    index = index % priv->inodes_per_blocks;
    for(int i=0;i<index;i++)
        inode_tmp++;
    memcpy(inode_buf, inode_tmp, sizeof(struct ext2_inode));
    sys_free2(block_buf, priv->blocksize);
}

static void ext2_write_inode(struct ext2_inode *inode_buf, u32 inode, u32 dev, struct ext2_priv_data *priv)
{
    if(inode == 1717)
        inode = 1717;
    int bg = (inode-1) / priv->sb.s_inodes_per_group;
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor *bgd = (struct bg_descriptor *)block_buf + bg;
    int index = (inode - 1) % priv->sb.s_inodes_per_group;
    int block = (index * sizeof(struct ext2_inode)) / priv->blocksize;
    int inode_table = bgd->bg_inode_table;
    ext2_read_block(block_buf, bgd->bg_inode_table + block, dev, priv);
    struct ext2_inode *inode_tmp = (struct ext2_inode *)block_buf;
    index = index % priv->inodes_per_blocks;
    for(int i=0;i<index;i++)
        inode_tmp++;
    memcpy(inode_tmp, inode_buf, sizeof(struct ext2_inode));
    ext2_write_block(block_buf, inode_table + block, dev, priv);
    sys_free2(block_buf, priv->blocksize);
}

static void ext2_write_all_superblock(u8 *buf, u32 dev, struct ext2_priv_data *priv)
{
    //revision 0: all block group have a superblock and block group decriptor table
    if(priv->sb.s_rev_level == 0)
    {
        int sb_block = priv->sb.s_first_data_block;
        for(int i=0;i<priv->bg_num;i++, sb_block += priv->sb.s_blocks_per_group)
            ext2_write_block(buf, sb_block, dev, priv);
    }
    //rivision 1 and later: superblock and group descriptor table backups are 
    // in the groups 0, 1 and those whose id are the power of 3, 5, 7
    else
    {
        int sb_block = priv->sb.s_first_data_block;
        ext2_write_block(buf, sb_block, dev, priv);     //group 0
        ext2_write_block(buf, sb_block + priv->sb.s_blocks_per_group, dev, priv);   //group 1
        sb_block = sb_block + priv->sb.s_blocks_per_group;
        for(int i=2;i<priv->bg_num;i++)
        {
            if(is_A_Power_Of_B(i, 3) || is_A_Power_Of_B(i, 5) || is_A_Power_Of_B(i, 7))
            {
                ext2_write_block(buf, sb_block, dev, priv);
            }
            sb_block = sb_block + priv->sb.s_blocks_per_group;
        }
    }
}

static void ext2_write_all_bgdt(u8 *buf, u32 dev, struct ext2_priv_data *priv)
{
    //revision 0: all block group have a superblock and block group decriptor table
    if(priv->sb.s_rev_level == 0)
    {
        int bgdt_block = priv->sb.s_first_data_block + 1;
        for(int i=0;i<priv->bg_num;i++, bgdt_block += priv->sb.s_blocks_per_group)
            ext2_write_block(buf, bgdt_block, dev, priv);
    }
    //rivision 1 and later: superblock and group descriptor table backups are 
    // in the groups 0, 1 and those whose id are the power of 3, 5, 7
    else
    {
        int bgdt_block = priv->sb.s_first_data_block +1;
        ext2_write_block(buf, bgdt_block, dev, priv);     //group 0
        ext2_write_block(buf, bgdt_block + priv->sb.s_blocks_per_group, dev, priv);   //group 1
        bgdt_block = bgdt_block + priv->sb.s_blocks_per_group;
        for(int i=2;i<priv->bg_num;i++)
        {
            if(is_A_Power_Of_B(i, 3) || is_A_Power_Of_B(i, 5) || is_A_Power_Of_B(i, 7))
            {
                ext2_write_block(buf, bgdt_block, dev, priv);
            }
            bgdt_block = bgdt_block + priv->sb.s_blocks_per_group;
        }
    }
}

static int ext2_read_singly_linked(u8 *buf, u32 block, u32 start_block, u32 count, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    u8 *block_buf2 = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    int maxblocks = priv->blocksize / 4 - start_block;

	ext2_read_block(block_buf, block, dev, priv);
    u32 *pblock = (u32 *)block_buf + start_block;
    int i, byte_nr = 0;
	for(i=0;i<maxblocks; i++)
	{
	    if(pblock[i] == 0 || byte_nr >= count) break;
        ext2_read_block(block_buf2, pblock[i], dev, priv);
        if(count - byte_nr > priv->blocksize)
        {
            memcpy(buf+byte_nr, block_buf2, priv->blocksize);
            byte_nr += priv->blocksize;
        }
        else
        {
            memcpy(buf+byte_nr, block_buf2, count-byte_nr);
            byte_nr = count;
        }
	}
    sys_free2(block_buf, priv->blocksize);
    sys_free2(block_buf2, priv->blocksize);
	return byte_nr;
}

static int ext2_write_singly_linked(const char *buf, u32 block, u32 inode, struct ext2_inode *inode_buf, 
                u32 start_block, u32 count, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    u8 *block_buf2 = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    int maxblocks = priv->blocksize / 4 - start_block;

    ext2_read_block(block_buf, block, dev, priv);
    u32 *pblock = (u32 *)block_buf + start_block;
    int i, byte_nr = 0;
    for(i=0;i<maxblocks;i++)
    {
        if(byte_nr >= count) break;
        if(pblock[i] == 0)
        {
            pblock[i] = ext2_alloc_block(inode, inode_buf, dev, priv);
            ext2_write_block(block_buf, block, dev, priv);
        }
        ext2_read_block(block_buf2, pblock[i], dev, priv);
        if(count-byte_nr > priv->blocksize)
        {
            memcpy(block_buf2, buf, priv->blocksize);
            byte_nr += priv->blocksize;
        }
        else
        {
            memcpy(block_buf2, buf, count-byte_nr);
            byte_nr = count;
        }
        ext2_write_block(block_buf2, pblock[i], dev, priv);
    }
    sys_free2(block_buf, priv->blocksize);
    sys_free2(block_buf2, priv->blocksize);
    return byte_nr;
}

//index为要读取文件的起始读取块ID（从0开始）
static int ext2_read_doubly_linked(u8 *buf, u32 block, u32 doubly_offset, u32 singly_offset, u32 count, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    int maxblocks = priv->blocksize / 4 - doubly_offset;
    ext2_read_block(block_buf, block, dev, priv);
    u32 *pblock = (u32 *)block_buf + doubly_offset;
    int i, byte_nr = 0;
    byte_nr += ext2_read_singly_linked(buf+byte_nr, *pblock, singly_offset, count-byte_nr, dev, priv);
    for(i=1;i<maxblocks;i++)
    {
        int byte_read;
        if(pblock[i] == 0 || byte_nr >= count)
            break;
        byte_read = ext2_read_singly_linked(buf+byte_nr, pblock[i], 0, count-byte_nr, dev, priv);
        byte_nr += byte_read;
    }
    sys_free2(block_buf, priv->blocksize);
    return byte_nr;
}

static int ext2_write_doubly_linked(const char *buf, u32 block, u32 inode, struct ext2_inode *inode_buf,
                        u32 doubly_offset, u32 singly_offset, u32 count, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    int maxblocks = priv->blocksize / 4 - doubly_offset;
    ext2_read_block(block_buf, block, dev, priv);
    u32 *pblock = (u32 *)block_buf + doubly_offset;
    int i, byte_nr = 0;
    byte_nr += ext2_write_singly_linked(buf+byte_nr, *pblock, inode, inode_buf, singly_offset, count-byte_nr, dev, priv);
    for(i=1;i<maxblocks;i++)
    {
        int byte_read;
        if(byte_nr >= count)
            break;
        if(pblock[i] == 0)
        {
            pblock[i] = ext2_alloc_block(inode, inode_buf, dev, priv);
            ext2_write_block(block_buf, block, dev, priv);
        }
        byte_read = ext2_write_singly_linked(buf+byte_nr, pblock[i], inode, inode_buf, 0, count-byte_nr, dev, priv);
        byte_nr += byte_read;
    }
    sys_free2(block_buf, priv->blocksize);
    return byte_nr;    
}

static int ext2_read_triply_linked(u8 *buf, u32 block, u32 triply_offset, u32 doubly_offset, u32 singly_offset, u32 count, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    int maxblocks = priv->blocksize / 4 - triply_offset;
    ext2_read_block(block_buf, block, dev, priv);
    u32 *pblock = (u32 *)block_buf + triply_offset;
    int i, byte_nr = 0;
    byte_nr += ext2_read_doubly_linked(buf+byte_nr, *pblock, doubly_offset, singly_offset, count-byte_nr, dev, priv);
    for(i=1;i<maxblocks;i++)
    {
        int byte_read;
        if(pblock[i] == 0 || byte_nr >= count)
            break;
        byte_read = ext2_read_doubly_linked(buf+byte_nr, *pblock, 0, 0, count-byte_nr, dev, priv);
        byte_nr += byte_read;
    }
    sys_free2(block_buf, priv->blocksize);
    return byte_nr;
}

static int ext2_write_triply_linked(u8 *buf, u32 block, u32 inode, struct ext2_inode *inode_buf, 
                                u32 triply_offset, u32 doubly_offset, u32 singly_offset, u32 count, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    int maxblocks = priv->blocksize / 4 - triply_offset;
    ext2_read_block(block_buf, block, dev, priv);
    u32 *pblock = (u32 *)block_buf + triply_offset;
    int i, byte_nr = 0;
    byte_nr += ext2_write_doubly_linked((char*)buf+byte_nr, *pblock, inode, inode_buf, doubly_offset, singly_offset, count-byte_nr, dev, priv);
    for(i=1;i<maxblocks;i++)
    {
        int byte_read;
        if(pblock[i] == 0 || byte_nr >= count)
            break;
        byte_read = ext2_write_doubly_linked((char *)buf+byte_nr, *pblock, inode, inode_buf, 0, 0, count-byte_nr, dev, priv);
        byte_nr += byte_read;
    }
    sys_free2(block_buf, priv->blocksize);
    return byte_nr;
}


// Set block bitmap when allocating a block
static void ext2_set_block(u32 block, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor *bg = (struct bg_descriptor *)block_buf;
    bg = bg + block / priv->sb.s_blocks_per_group;
    ext2_write_all_bgdt(block_buf, dev, priv);
    int bmap = bg->bg_block_bitmap;
    ext2_read_block(block_buf, bg->bg_block_bitmap, dev, priv);
    u8 *pbmap = (u8 *)block_buf;
    int index = block % priv->sb.s_blocks_per_group;
    for(int i=0;i<index/8;i++)
            pbmap++;
    int shift = index % 8 - 1;
    if(*pbmap & (1 << shift))
        return ;                            //that bit has already been set
    *pbmap |= (1 << shift);
    // kprintf("free blockid:%d\n",index * 8 + shift + 1);
    ext2_write_block(block_buf, bmap, dev, priv);
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    bg->bg_free_blocks_count--;
    ext2_write_all_bgdt(block_buf, dev, priv);

    ext2_read_block(block_buf, priv->sb.s_first_data_block, dev, priv);
    struct ext2_superblock *sb = (struct ext2_superblock *)block_buf;
    sb->s_free_blocks_count--;
    ext2_write_all_superblock(block_buf, dev, priv);
    sys_free2(block_buf, priv->blocksize);
}

// free an allocated block 
// NOTE: this function will not check if that block is a special block like superblock or bitmap
static void ext2_free_block(u32 block, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor *bg = (struct bg_descriptor *)block_buf;
    bg = bg + block / priv->sb.s_blocks_per_group;
    int bmap = bg->bg_block_bitmap;
    ext2_read_block(block_buf, bg->bg_block_bitmap, dev, priv);
    u8 *pbmap = (u8 *)block_buf;
    int index = block % priv->sb.s_blocks_per_group;
    for(int i=0;i<index/8;i++)
            pbmap++;
    int shift = index % 8 - 1;
    if(!(*pbmap & (1 << shift)))
        return ;
    *pbmap &= ~(1 << shift);
    // kprintf("free blockid:%d\n",index * 8 + shift + 1);
    ext2_write_block(block_buf, bmap, dev, priv);

    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    bg->bg_free_blocks_count++;
    ext2_write_all_bgdt(block_buf, dev, priv);
    ext2_read_block(block_buf, priv->sb.s_first_data_block, dev, priv);
    struct ext2_superblock *sb = (struct ext2_superblock *)block_buf;
    sb->s_free_blocks_count++;
    ext2_write_all_superblock(block_buf, dev, priv);
    sys_free2(block_buf, priv->blocksize);
}

//  allocate an unused block and return its blockid
static int ext2_alloc_block(u32 inode_id, struct ext2_inode *inode_buf, u32 dev, struct ext2_priv_data *priv)
{
    int res = 0;
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc((priv->blocksize)));
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor *bg = (struct bg_descriptor *)block_buf;
    int i = (inode_id - 1) / priv->sb.s_inodes_per_group;
    if(!bg[i].bg_free_blocks_count)
    {
        for(i=0;i<priv->bg_num;i++)
            if(bg[i].bg_free_blocks_count)
                break;
    }
    if(i == priv->bg_num)
        goto end;
    int bmap = bg[i].bg_block_bitmap;
    ext2_read_block(block_buf, bmap, dev, priv);
    u8 *pbmap = (u8 *)block_buf;
    int index, shift;
    for(index=0;index<priv->blocksize;index++, pbmap++)
    {
        if(*pbmap != 0xff) break;           //Found a unallocated bit;
    }
    if(index == priv->blocksize) 
        goto end;                           //out of range, fail to allocate
    for(shift=0;shift<8;shift++)
    {
        if(!(*pbmap & (1 << shift)))       
        {                                   
            *pbmap |= (1 << shift);
            break;                          
        }
    }
    ext2_write_block(block_buf, bmap, dev, priv);
    inode_buf->i_blocks += priv->blocksize / 512;
    inode_buf->i_size += priv->blocksize;

    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    bg = (struct bg_descriptor *)block_buf;
    bg[i].bg_free_blocks_count--;
    ext2_write_all_bgdt(block_buf, dev, priv);      //update bgdt
    ext2_read_block(block_buf, priv->sb.s_first_data_block, dev, priv);
    struct ext2_superblock *sb = (struct ext2_superblock *)block_buf;
    sb->s_free_blocks_count--;
    ext2_write_all_superblock(block_buf, dev, priv);        //update superblocks

    // kprintf("index:%d, shift:%d\n", index, shift);
    res = (priv->sb.s_first_data_block + i * priv->sb.s_blocks_per_group + index * 8 + shift);     //cauculate the blockid
    memset(block_buf, 0, priv->blocksize);
    ext2_write_block(block_buf, res, dev, priv);
end:
    // sys_free2(inode_buf, sizeof(struct ext2_inode));
    sys_free2(block_buf, priv->blocksize);
    return res;
}



void ext2_create_root_dir(u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    // u8 block_buf[BLOCKSIZE];
    memset(block_buf, 0, priv->blocksize);
    int entry_len = sizeof(struct ext2_dir_entry) + sizeof(".") -1;      
    int pad_len = entry_len % 4 ? 4- entry_len %4 : 0;
    // kprintf("entry_len:%d  pad_len:%d\n",entry_len, pad_len);
    //"." 's entry
    struct ext2_dir_entry *dir_entry = (struct ext2_dir_entry *)K_PHY2LIN(sys_kmalloc(entry_len + pad_len));
    memset(dir_entry, 0, entry_len + pad_len);
    dir_entry->inode = 2;
    dir_entry->rec_len = entry_len + pad_len;
    dir_entry->name_len = sizeof(".")-1;
    memcpy(dir_entry->name, ".", sizeof(".")-1);
    memset(dir_entry->name + dir_entry->name_len, 0, pad_len);

    int root_dir_block = 219;           //first unused block
    ext2_set_block(219, dev, priv);
    memset(block_buf, 0, priv->blocksize);
    memcpy(block_buf, dir_entry, dir_entry->rec_len);

    //".." 's entry
    entry_len++, pad_len--;
    dir_entry->name_len++;
    // dir_entry->rec_len = 12;
    dir_entry->rec_len = priv->blocksize - 12;
    memcpy(dir_entry->name, "..", sizeof("..")-1);
    memcpy(block_buf+12, dir_entry, entry_len + pad_len);

    // //the last entry
    // dir_entry->inode = 0;
    // dir_entry->name_len = 0;
    // dir_entry->rec_len = priv->blocksize - 2 * dir_entry->rec_len;
    // memcpy(block_buf+24, dir_entry, sizeof(struct ext2_dir_entry));

    ext2_write_block(block_buf, root_dir_block, dev, priv);

    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor *bg = (struct bg_descriptor *)block_buf;
    bg[0].bg_used_dirs_count++;
    ext2_write_all_bgdt(block_buf, dev, priv);
    int inode_table = ((struct bg_descriptor *) block_buf)->bg_inode_table;
    ext2_read_block(block_buf, inode_table, dev, priv);
    struct ext2_inode *inode_tmp = (struct ext2_inode *)block_buf;
    inode_tmp[1].i_mode = EXT2_S_IFDIR | EXT2_S_IRUSR | EXT2_S_IWUSR | EXT2_S_IWUSR |
                          EXT2_S_IXUSR | EXT2_S_IRGRP | EXT2_S_IXGRP | EXT2_S_IROTH | 
                          EXT2_S_IXOTH;
    inode_tmp[1].i_uid = 0;
    inode_tmp[1].i_links_count = 2;
    inode_tmp[1].i_size = priv->blocksize;
    inode_tmp[1].i_blocks = 2;           //512-bytes blocks that this inode occupied 
    inode_tmp[1].i_block[0] = root_dir_block;
    inode_tmp[1].i_osd1 = 1;
    inode_tmp[1].i_file_acl = inode_tmp[1].i_dir_acl = inode_tmp[1].i_faddr = 0;
    memset(inode_tmp[1].i_osd2, 0, sizeof(inode_tmp[1].i_osd2));
    ext2_write_block(block_buf, inode_table, dev, priv);
    sys_free2(block_buf, priv->blocksize);
    sys_free2(dir_entry, entry_len+pad_len);
}

// allocated an unused inode and return its id
static int ext2_alloc_inode(const char *fullpath, u32 dev, struct ext2_priv_data *priv)
{
    int res = 0;
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor* bg = (struct bg_descriptor *)block_buf;
    int parent_inode = ext2_find_file_inode(fullpath, inode_buf, dev, priv);
    // int i = strcmp("/", fullpath) ? 0 : 1;          //root directory is in block group 0
    int i;
    if(!strcmp(fullpath, "/"))                      //parent directory is root directory
    {
        u32 min_free_inodes_bg = -1, index;
        for(i=0;i<priv->bg_num;i++)
        {   
            if(bg[i].bg_free_inodes_count < min_free_inodes_bg)
            {
                min_free_inodes_bg = bg[i].bg_free_inodes_count;
                index = i;
            }
        }
        
        bg += index;
        for(i=1;i<priv->bg_num;i++, bg++)
            if(bg->bg_free_inodes_count)
                break;
        if(i == priv->bg_num)
            goto end;
    }
    else
    {
        i = (parent_inode - 1) / priv->sb.s_inodes_per_group;
        bg += i;
        if(!bg->bg_free_inodes_count)
            goto end;
    }

    // kprintf("parent_inode:%d, path:%s, bgid:%d\n", parent_inode, fullpath, i);

    bg->bg_free_inodes_count--;
    ext2_write_all_bgdt(block_buf, dev, priv);
    int bitmap = bg->bg_inode_bitmap;
    ext2_read_block(block_buf, bitmap, dev, priv);
    u8 *pimap = block_buf;
    int index, shift;
    for(index=0;index<priv->sb.s_inodes_per_group/8;index++, pimap++)
    {
        if(*pimap != 0xff)
            break;
    }
    if(index == priv->sb.s_inodes_per_group / 4) 
        goto end;
    for(shift=0;shift<8;shift++)
    {
        if(!(*pimap & (1 << shift)))      
        {                                   
            *pimap |= (1 << shift);
            break;                          
        }
    }
    ext2_write_block(block_buf, bitmap, dev, priv);
    ext2_read_block(block_buf, priv->sb.s_first_data_block, dev, priv);
    struct ext2_superblock *sb = (struct ext2_superblock *)block_buf;
    sb->s_free_inodes_count--;
    ext2_write_all_superblock(block_buf, dev, priv);
    //inode从1开始编号（0表示未使用）
    res = i * priv->sb.s_inodes_per_group + index * 8 + shift + 1;  
end:
    sys_free2(block_buf, priv->blocksize);
    sys_free2(inode_buf, sizeof(struct ext2_inode));
    return res;
}

static void ext2_free_inode(u32 inode_id, u32 dev, struct ext2_priv_data *priv)
{
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor *bg = (struct bg_descriptor *)block_buf;
    bg = bg + inode_id / priv->sb.s_inodes_per_group;
    
    int imap = bg->bg_inode_bitmap;
    ext2_read_block(block_buf, bg->bg_inode_bitmap, dev, priv);
    u8 *pimap = (u8 *)block_buf;
    int index = inode_id % priv->sb.s_inodes_per_group;
    for(int i=0;i<index/8;i++)
            pimap++;
    int shift = index % 8 - 1;
    if(!(*pimap & (1 << shift)))
        return ;
    *pimap &= ~(1 << shift);
    ext2_write_block(block_buf, imap, dev, priv);

    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    bg->bg_free_inodes_count++;
    ext2_write_all_bgdt(block_buf, dev, priv);
    ext2_read_block(block_buf, priv->sb.s_first_data_block, dev, priv);
    struct ext2_superblock *sb = (struct ext2_superblock *)block_buf;
    sb->s_free_inodes_count++;
    ext2_write_all_superblock(block_buf, dev, priv);
    sys_free2(block_buf, priv->blocksize);
}

//search a file in a directory and return its inode id
//return 0 if not found
static int ext2_search_file_in_directory(char *filename, struct ext2_dir_entry *dir_start, u32 dev, struct ext2_priv_data *priv)
{
    char name[255];
    struct ext2_dir_entry *dir = dir_start;
    int temp = 0;
    while(temp < priv->blocksize)
    {
        temp += dir->rec_len;
        memcpy(name, dir->name, dir->name_len);
        name[dir->name_len] = '\0';
        if(filename && !strcmp(filename, name))
            return dir->inode;              //file found
        dir = (struct ext2_dir_entry *)((u8 *)dir + dir->rec_len);
    }
    return 0;
}


//Search for an inode by its full path
// return its inode id if succeed, otherwise return 0
static int ext2_find_file_inode(const char *fullpath, struct ext2_inode *inode, u32 dev, struct ext2_priv_data *priv)
{
    if(!strcmp("/", fullpath))
    {
        ext2_read_inode(inode, 2, dev, priv);
        return 2;
    }
    else if(!strcmp("", fullpath))
        return 0;
    char filenames[strlen(fullpath)+1], *pname = filenames;
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    memcpy(filenames, fullpath, strlen(fullpath)+1);
    int n = split_path(filenames);
    pname++;        //skip the first '/'
    if(n > 1)
    {
        //search the root directory first
        int block_id, inode_id;
        ext2_read_inode(inode_buf, 2, dev, priv);
        while(n--)
        {
            int i;
            for(i=0;i<12;i++)
            {
                block_id = inode_buf->i_block[i], inode_id;
                if(!block_id)
                    goto fail;
                ext2_read_block(block_buf, block_id, dev, priv);
                inode_id = ext2_search_file_in_directory(pname, (struct ext2_dir_entry *)block_buf, dev, priv);
                if(inode_id)
                    break;
            }
            if(i == 12 && !inode_id)
                goto fail;
        next:
            pname += strlen(pname) + 1;
            ext2_read_inode(inode_buf, inode_id, dev, priv);
        }
        memcpy(inode, inode_buf, sizeof(struct ext2_inode));
        sys_free2(block_buf, priv->blocksize);
        sys_free2(inode_buf, sizeof(struct ext2_inode));
        return inode_id;
    }
    else
    {
        int block_id, inode_id, i;
        ext2_read_inode(inode_buf, 2, dev, priv);
        for(i=0;i<12;i++)
        {
            block_id = inode_buf->i_block[i];
            if(!block_id)
                goto fail;
            ext2_read_block(block_buf, block_id, dev, priv);
            inode_id = ext2_search_file_in_directory(pname, (struct ext2_dir_entry *)block_buf, dev, priv);
            if(inode_id)
                break;
        }
        if(i == 12 && !inode_id)
            goto fail;
        ext2_read_inode(inode, inode_id, dev, priv);
        // kprintf("%s found inode id is :%d", pname, inode_id);
        sys_free2(block_buf, priv->blocksize);
        sys_free2(inode_buf, sizeof(struct ext2_inode));
        return inode_id;
    }

    fail:
    // kprintf("File %s not found!\n", pname);
    sys_free2(block_buf, priv->blocksize);
    sys_free2(inode_buf, sizeof(struct ext2_inode));
    return 0;
}

static void ext2_new_entry(u32 dir_inode, struct ext2_dir_entry *new_entry, u32 dev, struct ext2_priv_data *priv)
{
    if(!dir_inode)
        return ;
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    struct ext2_dir_entry *dir_entry;
    int i, block_id;
    int entry_len = sizeof(struct ext2_dir_entry) + new_entry->name_len;
    int pad_len = entry_len % 4 ? 4 - entry_len % 4: 0;
    ext2_read_inode(inode_buf, dir_inode, dev, priv);
    for(i=0;i<12;i++)
    {
        block_id = inode_buf->i_block[i];
        if(!block_id)
        {
            block_id = inode_buf->i_block[i] = ext2_alloc_block(dir_inode, inode_buf, dev, priv);
            memset(block_buf, 0, priv->blocksize);
            dir_entry = (struct ext2_dir_entry *)block_buf;
            new_entry->rec_len = entry_len + pad_len;
            break;
        }
        ext2_read_block(block_buf, block_id, dev, priv);
        dir_entry = (struct ext2_dir_entry *)block_buf;
        int tmp = 0;
        while(tmp + dir_entry->rec_len < priv->blocksize)
        {
            tmp += dir_entry->rec_len;
            dir_entry = (struct ext2_dir_entry *)((u8 *)dir_entry + dir_entry->rec_len);
        }
        int __entry_len = sizeof(struct ext2_dir_entry) + dir_entry->name_len;      //length of the last entry
        __entry_len += 4 - __entry_len % 4;         //padding
        int empty_space = dir_entry->rec_len - __entry_len;
        if(empty_space > entry_len + pad_len)
        {
            dir_entry->rec_len = __entry_len;
            dir_entry = (struct ext2_dir_entry *)((u8 *)dir_entry + dir_entry->rec_len);
            new_entry->rec_len = empty_space;
            break;
        }
    }   
    memcpy(dir_entry, new_entry, entry_len + pad_len);
    ext2_write_block(block_buf, block_id, dev, priv);
    sys_free2(inode_buf, sizeof(struct ext2_inode));
    sys_free2(block_buf, priv->blocksize);
}

// Create a directory entry under an EXISTED path   (like mkdir)
static int ext2_create_dir(const char *fullpath, char *dirname, u32 dev, struct ext2_priv_data *priv)
{   
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    int parent_directory = ext2_find_file_inode(fullpath, inode_buf, dev, priv);
    if(!parent_directory)
    {
        sys_free2(inode_buf, sizeof(struct ext2_inode));
        kprintf("No such directory\n");
        return 0;
    }
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    int entry_len = sizeof(struct ext2_dir_entry) + strlen(dirname);
    int pad_len = entry_len % 4 ? 4 - entry_len % 4: 0;

    //Insert directroy entry

    int inode_id;
    struct ext2_dir_entry *dir_entry = (struct ext2_dir_entry *)K_PHY2LIN(sys_kmalloc(entry_len + pad_len));
    memcpy(dir_entry->name, dirname, strlen(dirname));
    dir_entry->name_len = strlen(dirname);
    inode_id = dir_entry->inode = ext2_alloc_inode(fullpath, dev, priv);
    memset((u8 *)dir_entry->name + dir_entry->name_len, 0, pad_len);
    ext2_new_entry(parent_directory, dir_entry, dev, priv);

    // kprintf("inode_id:%d\n", inode_id);
    memset(inode_buf, 0, sizeof(inode_buf));
    inode_buf->i_mode =   EXT2_S_IFDIR | EXT2_S_IRUSR | EXT2_S_IWUSR | EXT2_S_IWUSR |
                          EXT2_S_IXUSR | EXT2_S_IRGRP | EXT2_S_IXGRP | EXT2_S_IROTH | 
                          EXT2_S_IXOTH;
    inode_buf->i_block[0] = ext2_alloc_block(inode_id, inode_buf, dev, priv);
    // kprintf("i_block[0]:%d\n", inode_buf->i_block[0]);
    inode_buf->i_blocks = 2;
    inode_buf->i_links_count = 2;
    inode_buf->i_file_acl = inode_buf->i_dir_acl = inode_buf->i_faddr = 0;
    inode_buf->i_osd1 = 1;

    ext2_write_inode(inode_buf, inode_id, dev, priv);

    //Create "." and ".."
    sys_free2(dir_entry, entry_len + pad_len);
    memset(block_buf, 0, priv->blocksize);
    entry_len = sizeof(struct ext2_dir_entry) + strlen(".");        //9
    pad_len = entry_len % 4 ? (4 - entry_len % 4) : 0;                  //3
    dir_entry = (struct ext2_dir_entry *)K_PHY2LIN(sys_kmalloc(entry_len + pad_len));
    dir_entry->inode = inode_id;
    dir_entry->name_len = 1;
    dir_entry->rec_len = entry_len + pad_len;
    memcpy(dir_entry->name, ".", 1);
    memcpy(block_buf, dir_entry, pad_len + entry_len);

    entry_len++, pad_len--;
    dir_entry->inode = parent_directory;
    dir_entry->name_len = 2;
    dir_entry->rec_len = priv->blocksize - (entry_len + pad_len);
    memcpy(dir_entry->name, "..", 2);
    memcpy(block_buf + 12, dir_entry, entry_len + pad_len);

    // //the last entry
    // dir_entry->inode = 0;
    // dir_entry->name_len = 0;
    // dir_entry->rec_len = priv->blocksize - 2 * 12;
    // memcpy(block_buf + 24, dir_entry, sizeof(struct ext2_dir_entry));

    ext2_write_block(block_buf, inode_buf->i_block[0], dev, priv);

    //update parent directory's link count
    ext2_read_inode(inode_buf, parent_directory, dev, priv);
    inode_buf->i_links_count++;
    ext2_write_inode(inode_buf, parent_directory, dev, priv);

    //update GDT
    int index = (inode_id - 1) / priv->sb.s_inodes_per_group;
    ext2_read_block(block_buf, priv->first_bgd, dev, priv);
    struct bg_descriptor *bg = (struct bg_descriptor *)block_buf;
    bg[index].bg_used_dirs_count++;
    ext2_write_all_bgdt(block_buf, dev, priv);
    
    sys_free2(block_buf, priv->blocksize);
    sys_free2(inode_buf, sizeof(struct ext2_inode));
    return 1;
}

static int ext2_create_file(const char *fullpath, char *filename, u32 dev, struct ext2_priv_data *priv)
{
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    int parent_directory = ext2_find_file_inode(fullpath, inode_buf, dev, priv);
    if(!parent_directory)
    {
        sys_free2(inode_buf, sizeof(struct ext2_inode));
        return 0;
    }

    int entry_len = sizeof(struct ext2_dir_entry) + strlen(filename);
    int pad_len = 4 - entry_len % 4;
    
    int inode_id;
    struct ext2_dir_entry *dir_entry = (struct ext2_dir_entry *)K_PHY2LIN(pad_len + entry_len);
    dir_entry->name_len = strlen(filename);
    memcpy(dir_entry->name, filename, dir_entry->name_len);
    inode_id = dir_entry->inode = ext2_alloc_inode(fullpath, dev, priv);
    memset((u8 *)dir_entry->name + dir_entry->name_len, 0, pad_len);
    ext2_new_entry(parent_directory, dir_entry, dev, priv);

    memset(inode_buf, 0, sizeof(struct ext2_inode));
    inode_buf->i_mode = EXT2_S_IFREG | EXT2_S_IRUSR | EXT2_S_IWUSR | EXT2_S_IRGRP | EXT2_S_IROTH;
    inode_buf->i_size = 0;
    inode_buf->i_links_count = 1;
    inode_buf->i_osd1 = 1;
    inode_buf->i_blocks = 0;
    ext2_write_inode(inode_buf, inode_id, dev, priv);

    sys_free2(inode_buf, sizeof(struct ext2_inode));
    return inode_id;
}

static int ext2_open_file(MESSAGE *fs_msg, u32 dev, struct ext2_priv_data *priv)
{
    int fd = -1;
    char path_buf[MAX_PATH];
    struct ext2_inode inode_buf;
	memcpy((void*)va2la(fs_msg->source, path_buf), (void*)va2la(fs_msg->source, fs_msg->PATHNAME), fs_msg->NAME_LEN);
    path_buf[fs_msg->NAME_LEN] = '\0';
    int file_inode = ext2_find_file_inode(path_buf, &inode_buf, dev, priv);
    if(!file_inode)
    {
        if(!(fs_msg->FLAGS & O_CREAT))
            return -1;
        char *filename, *path = path_buf;
        int index;
        for(index=strlen(path_buf)-1;path_buf[index]!='/';index--);
        path_buf[index] = '\0';
        filename = &path_buf[index]+1;
        file_inode = ext2_create_file(path, filename, dev, priv);
        ext2_read_inode(&inode_buf, file_inode, dev, priv);
        if(!file_inode)
            return -1;
    }
    
    assert(file_inode > 0);

    int i;

    for(i=0;i<NR_INODE;i++)
    {
        if(ext2_file_desc_table[i].i_cnt == 0)
        {
            ext2_file_desc_table[i].i_cnt++;
            ext2_file_desc_table[i].i_dev = MINOR(dev);
            ext2_file_desc_table[i].i_mode = fs_msg->FLAGS;
            ext2_file_desc_table[i].i_size = inode_buf.i_size;
            memcpy(ext2_file_desc_table[i].fullpath, fs_msg->PATHNAME, fs_msg->NAME_LEN);
            break;
        }
    }
    int fd_index = i;

    assert(i < NR_INODE);

    for(i=0;i<NR_FILES;i++)
    {
        if(p_proc_current->task.filp[i] == 0)
        {
            fd = i;
            break;
        }
    }
    // assert(0 <= fd && fd < NR_FILES);
    
    for(i=0;i<NR_FILE_DESC;i++)
        if(f_desc_table[i].flag == 0)
            break;

    if(fd != -1)
    {
        p_proc_current->task.filp[fd] = &f_desc_table[i];
        f_desc_table[i].flag = 1;
        f_desc_table[i].fd_node.fd_ext2_inode = &ext2_file_desc_table[fd_index];
        f_desc_table[i].fd_pos = 0;
        f_desc_table[i].dev_index = ext2_dev;
        f_desc_table[i].fd_mode = fs_msg->FLAGS;
    }
    // assert(i < NR_FILE_DESC);

    return fd;
}

static int ext2_write_file(const char *fullpath, const char *buf, int begin, int len, u32 dev, struct ext2_priv_data *priv)
{
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    char *path_buf = (char *)K_PHY2LIN(sys_kmalloc(strlen(fullpath)+1));
    memcpy(path_buf, fullpath, strlen(fullpath)+1);
    char *filename, *path = path_buf;
    int index, offset;
    for(index=strlen(path_buf)-1;path_buf[index]!='/';index--);
    if(index)
        path_buf[index] = '\0';
    else
        path = "/";
    filename = &path_buf[index]+1;              //split the filename and its path
    
    int file_inode = ext2_find_file_inode(fullpath, inode_buf, dev, priv);
    if(!file_inode)
    {
        kprintf("Error: file doesn't exist.\n");
        return -1;
    }
    else if(!(inode_buf->i_mode & EXT2_S_IFREG))
    {
        kprintf("Error: target inode is not used as regular file.\n");
        return -1;
    }
    
    index = begin / priv->blocksize;
    offset = begin % priv->blocksize;
    
    //firstly read/write the data in the middle of the data block 

    int byte_nr = (priv->blocksize - offset) > len ? len : (priv->blocksize - offset);
    if(index < 12)
    {
        if(inode_buf->i_block[index] == 0)
            inode_buf->i_block[index] = ext2_alloc_block(file_inode, inode_buf, dev, priv);

        ext2_read_block(block_buf, inode_buf->i_block[index], dev, priv);
        memcpy(block_buf+offset, buf, byte_nr);
        ext2_write_block(block_buf, inode_buf->i_block[index], dev, priv);
    }
    else if(index < SINGLY_LINKED_MAX)
    {
        if(inode_buf->i_block[12] == 0)
            inode_buf->i_block[12] = ext2_alloc_block(file_inode, inode_buf, dev, priv);
        ext2_read_block(block_buf, inode_buf->i_block[12], dev, priv);
        u32 *pblock = (u32 *)block_buf + index - 12;
        if(*pblock == 0)
        {
            *pblock = ext2_alloc_block(file_inode, inode_buf, dev, priv);
            ext2_write_block(block_buf, inode_buf->i_block[12], dev, priv);
        }
        u32 blockid= *pblock;
        ext2_read_block(block_buf, blockid, dev, priv);
        memcpy(block_buf+offset, buf, byte_nr);
        ext2_write_block(block_buf, blockid, dev, priv);
    }
    else if(index < DOUBLY_LINKED_MAX)
    {
        if(inode_buf->i_block[13] == 0)
            inode_buf->i_block[13] = ext2_alloc_block(file_inode, inode_buf, dev, priv);
        ext2_read_block(block_buf, inode_buf->i_block[13], dev, priv);
        u32 *pblock = (u32 *)block_buf + (index-SINGLY_LINKED_MAX)/(priv->blocksize / 4);
        if(*pblock == 0)
        {
            *pblock = ext2_alloc_block(file_inode, inode_buf, dev, priv);
            ext2_write_block(block_buf, inode_buf->i_block[13], dev, priv);
        }
        u32 blockid = *pblock;
        ext2_read_block(block_buf, *pblock, dev, priv);
        pblock =(u32 *) block_buf + (index-SINGLY_LINKED_MAX)%(priv->blocksize / 4);
        if(*pblock == 0)
        {
            *pblock = ext2_alloc_block(file_inode, inode_buf, dev, priv);
            ext2_write_block(block_buf, blockid, dev, priv);
        }
        blockid = *pblock;
        ext2_read_block(block_buf, *pblock, dev, priv);
        memcpy(block_buf+offset, buf, byte_nr);
        ext2_write_block(block_buf, blockid, dev, priv);
    }
    // 出于神秘的原因，只要这一段不注释，程序就会在运行至用户态shell前触发GP异常。我实在是弄不明白为什么，所以只能先注释掉了
    // 这一段是用于写三级索引块的，在下面的ext2_read_file函数里也有一段类似的代码，那一段和这一段注释掉其中之一程序就可以跑了
    // 不明白是什么原因，为了能跑先把这里注释掉了。反正磁盘大小也不足以验证这一块。
    // else if(index < TRIPLY_LINKED_MAX)
    // {
    //     if(inode_buf->i_block[14] == 0)
    //         inode_buf->i_block[14] = ext2_alloc_block(file_inode, inode_buf, dev, priv);
    //     ext2_read_block(block_buf, inode_buf->i_block[14], dev, priv);
    //     u32 *pblock = (u32 *)block_buf + (index-DOUBLY_LINKED_MAX)/(priv->blocksize * priv->blocksize / 16);
    //     if(*pblock == 0)
    //     {
    //         *pblock = ext2_alloc_block(file_inode, inode_buf, dev, priv);
    //         ext2_write_block(block_buf, inode_buf->i_block[14], dev, priv);
    //     }
    //     u32 blockid = *pblock;
    //     ext2_read_block(block_buf, *pblock, dev, priv);
    //     pblock = (u32 *)block_buf + (index-DOUBLY_LINKED_MAX) % (priv->blocksize * priv->blocksize / 16) / (priv->blocksize / 4);
    //     if(*pblock == 0 )
    //     {
    //         *pblock = ext2_alloc_block(file_inode, inode_buf, dev, priv);
    //         ext2_write_block(block_buf, blockid, dev, priv);
    //     }
    //     blockid = *pblock;
    //     ext2_read_block(block_buf, *pblock, dev, priv);
    //     pblock = (u32 *)block_buf + (index-DOUBLY_LINKED_MAX) % (priv->blocksize * priv->blocksize / 16) % (priv->blocksize / 4);
    //     if(*pblock == 0)
    //     {
    //         *pblock = ext2_alloc_block(file_inode, inode_buf, dev, priv);
    //         ext2_write_block(block_buf, blockid, dev, priv);
    //     }
    //     blockid = *pblock;
    //     ext2_read_block(block_buf, *pblock, dev, priv);
    //     memcpy(block_buf+offset, buf, byte_nr);
    //     ext2_write_block(block_buf, blockid, dev, priv);
    // }
    
        
    index++;

    while(byte_nr < len)        //now we read/write the entire block
    {  
        if(index < 12)
        {
            if(inode_buf->i_block[index] == 0)
                inode_buf->i_block[index] = ext2_alloc_block(file_inode, inode_buf, dev, priv);

            if(len-byte_nr > priv->blocksize)
            {
                memcpy(block_buf, buf+byte_nr, priv->blocksize);
                byte_nr += priv->blocksize;
            }
            else
            {
                ext2_read_block(block_buf, inode_buf->i_block[index], dev, priv);
                memcpy(block_buf, buf+byte_nr, len-byte_nr);
                byte_nr = len;
            }
            ext2_write_block(block_buf, inode_buf->i_block[index], dev, priv);
            if(byte_nr >= len)
                break;
            index++;
        }
        else if(index < SINGLY_LINKED_MAX)
        {
            if(inode_buf->i_block[12] == 0)
                inode_buf->i_block[12] = ext2_alloc_block(file_inode, inode_buf, dev, priv);
            int write_nr = ext2_write_singly_linked(buf+byte_nr, inode_buf->i_block[12], file_inode, inode_buf, index-12, len-byte_nr, dev, priv);
            int maxbytes = priv->blocksize * priv->blocksize / 4;
            if(write_nr >= maxbytes)
                index++;
            byte_nr += write_nr;
        }
        else if(index < DOUBLY_LINKED_MAX)
        {
            if(inode_buf->i_block[13] == 0)
                inode_buf->i_block[13] = ext2_alloc_block(file_inode, inode_buf, dev, priv);
            u32 singly_offset = (index-SINGLY_LINKED_MAX) % (priv->blocksize / 4), doubly_offset = (index-SINGLY_LINKED_MAX) / (priv->blocksize / 4);
            int write_nr = ext2_write_doubly_linked(buf+byte_nr, inode_buf->i_block[13], file_inode, inode_buf, doubly_offset, singly_offset, len-byte_nr, dev, priv);
            int maxbytes = priv->blocksize * priv->blocksize / 4 * priv->blocksize / 4;
            if(write_nr >= maxbytes)
                index++;
            byte_nr += write_nr;
        }
        else if(index < TRIPLY_LINKED_MAX)
        {
            if(inode_buf->i_block[14] == 0)
                inode_buf->i_block[14] = ext2_alloc_block(file_inode, inode_buf, dev, priv);
            u32 triply_offset = (index-TRIPLY_LINKED_MAX) / (priv->blocksize * priv->blocksize / 16);
            u32 doubly_offset = (index-TRIPLY_LINKED_MAX) % (priv->blocksize * priv->blocksize / 16) / (priv->blocksize / 4);
            u32 singly_offset = (index-TRIPLY_LINKED_MAX) % (priv->blocksize * priv->blocksize / 16) % (priv->blocksize / 4);
            int write_nr = ext2_write_triply_linked((u8 *)buf+byte_nr, inode_buf->i_block[14], file_inode, inode_buf, triply_offset, doubly_offset, singly_offset, len-byte_nr, dev, priv); 
        }
    }

    ext2_write_inode(inode_buf, file_inode, dev, priv);
    sys_free2(path_buf, strlen(fullpath)+1);
    sys_free2(block_buf, priv->blocksize);
    sys_free2(inode_buf, sizeof(struct ext2_inode));

    return byte_nr;
}

int ext2_read_file(const char *fullpath, char *buf, int begin, int len, u32 dev, struct ext2_priv_data *priv)
{
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    char *path_buf = (char *)K_PHY2LIN(sys_kmalloc(strlen(fullpath)+1));
    memcpy(path_buf, fullpath, strlen(fullpath)+1);
    char *filename, *path = path_buf;
    int index, offset;
    for(index=strlen(path_buf)-1;path_buf[index]!='/';index--);

    if(index)
        path_buf[index] = '\0';
    else
        path = "/";
    filename = &path_buf[index]+1;
    
    int file_inode = ext2_find_file_inode(fullpath, inode_buf, dev, priv);
    if(!file_inode)
    {
        kprintf("Error: file doesn't exist.\n");
        return -1;
    }
    else if(!(inode_buf->i_mode & EXT2_S_IFREG))
    {
        kprintf("Error: target inode is not used as regular file.\n");
        return -1;
    }

    if(begin > inode_buf->i_size)
        return 0;
    index = begin / priv->blocksize;
    offset = begin % priv->blocksize;
    int byte_nr = (priv->blocksize - offset) > len ? len : (priv->blocksize - offset);
    if(index < 12)
    {
        if(inode_buf->i_block[index] == 0)
            memset(buf, 0, byte_nr);
        else
        {   
            ext2_read_block(block_buf, inode_buf->i_block[index], dev, priv);
            memcpy(buf, block_buf+offset, byte_nr);
        }
    }
    else if(index < SINGLY_LINKED_MAX)
    {
        u32 *pblock = (u32 *)block_buf + (index - 12);
        ext2_read_block(block_buf, inode_buf->i_block[12], dev, priv);  
        if(*pblock == 0)
            memset(buf, 0, byte_nr);
        else
        {
            ext2_read_block(block_buf, *pblock, dev, priv);
            memcpy(buf, block_buf+offset, byte_nr);
        }
    }
    else if(index < DOUBLY_LINKED_MAX)
    {
        u32 *pblock = (u32 *)block_buf + (index - SINGLY_LINKED_MAX) / (priv->blocksize / 4);
        ext2_read_block(block_buf, inode_buf->i_block[13], dev, priv);
        if(*pblock == 0)
            memset(buf, 0, byte_nr);
        else
        {
            ext2_read_block(block_buf, *pblock, dev, priv);
            pblock = (u32 *)block_buf + (index-SINGLY_LINKED_MAX) % (priv->blocksize / 4);
            if(*pblock == 0)
                memset(buf, 0, byte_nr);
            else
            {
                ext2_read_block(block_buf, *pblock, dev, priv);
                memcpy(buf, block_buf+offset, byte_nr);
            }
        }
    }
    else if(index < TRIPLY_LINKED_MAX)
    {
        u32 *pblock = (u32 *)block_buf + (index - DOUBLY_LINKED_MAX) / (priv->blocksize * priv->blocksize / 16);
        ext2_read_block(block_buf, inode_buf->i_block[14], dev, priv);
        if(*pblock == 0)
            memset(buf, 0, byte_nr);
        else
        {
            ext2_read_block(block_buf, *pblock, dev, priv);
            pblock = (u32 *)block_buf + (index - DOUBLY_LINKED_MAX) % (priv->blocksize * priv->blocksize / 16) / (priv->blocksize / 4);
            if(*pblock == 0)
                memset(buf, 0, byte_nr);
            else
            {
                ext2_read_block(block_buf, *pblock, dev, priv);
                pblock = (u32 *)block_buf + (index - DOUBLY_LINKED_MAX) % (priv->blocksize * priv->blocksize / 16) % (priv->blocksize / 4);
                if(*pblock == 0)
                    memset(buf, 0, byte_nr);
                else
                {
                    ext2_read_block(block_buf, *pblock, dev, priv);
                    memcpy(buf, block_buf+offset, byte_nr);
                }
            }
        }
    }
    else
        return 0;
    
    index++;

    while(byte_nr < len)
    {   
        if(byte_nr > inode_buf->i_size)
            break;
        if(index < 12)
        {
            if(len-byte_nr > priv->blocksize)
            {
                if(inode_buf->i_block[index] == 0)
                    memset(buf+byte_nr, 0, priv->blocksize);
                else
                    ext2_read_block((u8*)buf+byte_nr, inode_buf->i_block[index], dev, priv);
                byte_nr += priv->blocksize;
            }
            else
            {
                ext2_read_block(block_buf, inode_buf->i_block[index], dev, priv);
                memcpy(buf+byte_nr, block_buf, len-byte_nr);
                byte_nr = len;
            }
            if(byte_nr >= len)
                break;
            index++;
        }
        else if(index < SINGLY_LINKED_MAX)
        {
            int read_nr = ext2_read_singly_linked((u8 *)buf+byte_nr, inode_buf->i_block[12], index-12, len-byte_nr, dev, priv);
            if(read_nr == 0)
                break;
            if(read_nr >= priv->blocksize * priv->blocksize / 4)
                index++;
            byte_nr += read_nr;
        }
        else if(index < DOUBLY_LINKED_MAX)      //256 * 256 + 256 + 12
        {
            u32 singly_offset = (index-SINGLY_LINKED_MAX) % (priv->blocksize / 4), doubly_offset = (index-SINGLY_LINKED_MAX) / (priv->blocksize / 4);
            int read_nr = ext2_read_doubly_linked((u8 *)buf+byte_nr, inode_buf->i_block[13], doubly_offset, singly_offset, len-byte_nr, dev, priv);
            byte_nr += read_nr;
            int maxblocks = priv->blocksize / 4 * priv->blocksize / 4;
            if(read_nr == 0)
                break;
            if(read_nr >= maxblocks)
                index++;
        }
        else if(index < TRIPLY_LINKED_MAX)
        {
            u32 triply_offset = (index-DOUBLY_LINKED_MAX) / (priv->blocksize * priv->blocksize / 16);
            u32 doubly_offset = (index-DOUBLY_LINKED_MAX) % (priv->blocksize * priv->blocksize / 16) / (priv->blocksize / 4);
            u32 singly_offset = (index-DOUBLY_LINKED_MAX) % (priv->blocksize * priv->blocksize / 16) % (priv->blocksize / 4);
            int read_nr = ext2_read_triply_linked((u8 *)buf+byte_nr, inode_buf->i_block[index], triply_offset, doubly_offset, singly_offset, len-byte_nr, dev, priv);
            int maxblocks = priv->blocksize / 4 * priv->blocksize / 4 * priv->blocksize / 4;
            byte_nr += read_nr;
            if(read_nr >= maxblocks)
                index++;
        }
        else
            break;
    }

    sys_free2(block_buf, priv->blocksize);
    sys_free2(inode_buf, sizeof(struct ext2_inode));
    sys_free2(path_buf, strlen(fullpath)+1);
    return byte_nr > len ? len : byte_nr;
}

static int ext2_unlink_file(const char *fullpath, u32 dev, struct ext2_priv_data *priv)
{
    int res = -1;
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    char *path_buf = (char *)K_PHY2LIN(sys_kmalloc(strlen(fullpath)+1));
    memcpy(path_buf, fullpath, strlen(fullpath)+1);
    char *filename, *path = path_buf;
    int index, offset;
    for(index=strlen(path_buf)-1;path_buf[index]!='/';index--);
    if(index)
        path_buf[index] = '\0';
    else
        path = "/";
    filename = &path_buf[index]+1;

    int parent_directory = ext2_find_file_inode(path, inode_buf, dev, priv);
    if(!parent_directory)
        goto end;
    int i, block_id; 
    char name_buf[255];
    struct ext2_dir_entry *dir_entry, *pre_dir_entry;
    for(i=0;i<12;i++)
    {
        block_id = inode_buf->i_block[i];
        ext2_read_block(block_buf, block_id, dev, priv);
        dir_entry = (struct ext2_dir_entry *)block_buf;
        int tmp = 0;
        while(tmp + dir_entry->rec_len <= priv->blocksize)
        {
            tmp += dir_entry->rec_len;
            memcpy(name_buf, dir_entry->name, dir_entry->name_len);
            name_buf[dir_entry->name_len] = '\0';
            if(!strcmp(name_buf, filename))
                goto found;
            pre_dir_entry = dir_entry;
            dir_entry = (struct ext2_dir_entry *)((u8 *)dir_entry + dir_entry->rec_len);
        }
    }
    if(i == 12)
        goto end;
found:
    ext2_read_inode(inode_buf, dir_entry->inode, dev, priv);
    if(inode_buf->i_mode & EXT2_S_IFDIR)
        goto end;
    if(inode_buf->i_links_count == 1)           //if it is the last link of this file, delete it.
    {
        for(i=0;i<12;i++)
        {
            if(inode_buf->i_block[i])
            {
                ext2_free_block(inode_buf->i_block[i], dev, priv);
                // kprintf("freed blocks: %d\n",inode_buf->i_block[i]);
                inode_buf->i_block[i] = 0;
            }
        }
        ext2_read_block(block_buf, inode_buf->i_block[12], dev, priv);
        u32 *pblock = (u32 *)block_buf;
        while((u8 *)pblock - block_buf < priv->blocksize)
        {
            if(*pblock)
                ext2_free_block(*pblock, dev, priv);
        }
        ext2_free_block(inode_buf->i_block[12], dev, priv);

        memset(inode_buf, 0, sizeof(struct ext2_inode));
        ext2_write_inode(inode_buf, dir_entry->inode, dev, priv);
        ext2_free_inode(dir_entry->inode, dev, priv);
    }
    else
    {
        inode_buf->i_links_count--;
        ext2_write_inode(inode_buf, dir_entry->inode, dev, priv);
    }   

    //delete entry
    int delete_len = dir_entry->rec_len;
    if((u8 *)dir_entry + dir_entry->rec_len >= block_buf + priv->blocksize)      //the last entry
    {
        pre_dir_entry->rec_len += dir_entry->rec_len;
        memset(dir_entry, 0, dir_entry->rec_len);
    }
    else
    {
        memcpy(dir_entry, (u8 *)dir_entry + dir_entry->rec_len, block_buf+priv->blocksize-(u8*)dir_entry);
        int tmp = 0;
        while(tmp + dir_entry->rec_len < priv->blocksize)   //find the last entry
        {
            tmp += dir_entry->rec_len;
            dir_entry = (struct ext2_dir_entry *)((u8 *)dir_entry + dir_entry->rec_len);
        }
        dir_entry->rec_len += delete_len;
    }
    ext2_write_block(block_buf, block_id, dev, priv);
    res = 0;


end:
    sys_free2(inode_buf, sizeof(struct ext2_inode));
    sys_free2(block_buf, priv->blocksize);
    sys_free2(path_buf, strlen(fullpath)+1);
    // sys_free2(name_buf);
    return res;
}

static int ext2_do_lseek(MESSAGE *fs_msg)
{
	int fd = fs_msg->FD;
	int off = fs_msg->OFFSET;
	int whence = fs_msg->WHENCE;

	int pos = p_proc_current->task.filp[fd]->fd_pos;
	//int f_size = p_proc_current->task.filp[fd]->fd_inode->i_size; //deleted by mingxuan 2019-5-17
	int f_size = p_proc_current->task.filp[fd]->fd_node.fd_ext2_inode->i_size;

	switch (whence) {
	case SEEK_SET:
		pos = off;
		break;
	case SEEK_CUR:
		pos += off;
		break;
	case SEEK_END:
		pos = f_size + off;
		break;
	default:
		return -1;
		break;
	}
	if ((pos > f_size) || (pos < 0)) {
		return -1;
	}
	p_proc_current->task.filp[fd]->fd_pos = pos;
	return pos;
}

static int ext2_do_getdents(const char *fullpath, struct linux_dirent *dirp, unsigned int count, u32 dev, struct ext2_priv_data *priv)
{
    struct ext2_inode *inode_buf = (struct ext2_inode *)K_PHY2LIN(sys_kmalloc(sizeof(struct ext2_inode)));
    u8 *block_buf = (u8 *)K_PHY2LIN(sys_kmalloc(priv->blocksize));
    int dir_inode = ext2_find_file_inode(fullpath, inode_buf, dev, priv);
    
    memset(dirp, 0, count);
    struct linux_dirent *_dirp = dirp;
    if(!dir_inode || !(inode_buf->i_mode & EXT2_S_IFDIR))
        return -1;
    int i, block_id;
    struct ext2_dir_entry *dir_entry;
    int byte_read = 0, offset = 0;
    for(i=0;i<12;i++)
    {
        ext2_read_inode(inode_buf, dir_inode, dev, priv);
        block_id = inode_buf->i_block[i];
        if(!block_id)
            break;
        ext2_read_block(block_buf, block_id, dev, priv);
        dir_entry = (struct ext2_dir_entry *)block_buf;
        int tmp = 0;
        while(tmp + dir_entry->rec_len <= priv->blocksize && dir_entry->rec_len)
        {
            _dirp->d_ino = dir_entry->inode;
            _dirp->d_off = offset;
            memcpy(_dirp->d_name, dir_entry->name, dir_entry->name_len);
            _dirp->d_name[dir_entry->name_len] = '\0';

            ext2_read_inode(inode_buf, dir_entry->inode, dev, priv);
            if(inode_buf->i_mode & EXT2_S_IFREG)
                _dirp->d_type = DIRENT_REG;
            else if(inode_buf->i_mode & EXT2_S_IFDIR)
                _dirp->d_type = DIRENT_DIR;

            _dirp->d_reclen = sizeof(struct linux_dirent) + strlen(_dirp->d_name) + 1;
            tmp += dir_entry->rec_len;
            dir_entry = (struct ext2_dir_entry *)((u8 *)dir_entry + dir_entry->rec_len);
            offset += _dirp->d_reclen;
            byte_read += _dirp->d_reclen;
            _dirp = (struct linux_dirent *)((u8 *)_dirp + _dirp->d_reclen);
        }
    }
    return byte_read;
}

