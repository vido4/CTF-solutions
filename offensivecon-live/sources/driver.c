#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/io.h>

#define MAX_MATRIX_NAME 16
#define DEF_MATRIX_ROWS 64
#define DEF_MATRIX_COLS 64
#define MAX_MATRIX_ROWS 1000
#define MAX_MATRIX_COLS 1000
#define DEF_MATRIX_NAME "default_matrix"

struct matrix
{
  int rows;                 // number of rows in the matrix
  int cols;                 // number of columns in the matrix
  uint8_t* data;            // 1-d backing data (rows x cols size)
  char name[MAX_MATRIX_NAME]; // name of the matrix
  struct matrix* link;      // linked peer
  struct task_struct* task; // owner of the object
  spinlock_t lock;          // fine grained locking
};


struct matrix_info
{
  int rows;
  int cols;
};

struct matrix_pos
{
  int row;
  int col;
  uint8_t byte;
};

#define IOCTL_MATRIX_SET_NAME _IOWR('s', 1, void*)
#define IOCTL_MATRIX_GET_NAME _IOWR('s', 2, void*)
#define IOCTL_MATRIX_GET_INFO _IOWR('s', 3, struct matrix_info)
#define IOCTL_MATRIX_SET_INFO _IOWR('s', 4, struct matrix_info)
#define IOCTL_MATRIX_GET_POS  _IOWR('s', 5, struct matrix_pos)
#define IOCTL_MATRIX_SET_POS  _IOWR('s', 6, struct matrix_pos)
#define IOCTL_MATRIX_DO_LINK  _IOWR('s', 7, int)

static int matrix_open(struct inode* inode, struct file* file);
static int matrix_release(struct inode* inode, struct file* file);
static int matrix_do_link(struct matrix* matrix, int ufd);

static void reset_matrix_locked(struct matrix* matrix)
{
  if (matrix)
  {
    matrix->rows = 0;
    matrix->cols = 0;
    if (matrix->link)
      matrix->link->link = NULL;
  }
}

static int bfs_matrix_pos(
  struct matrix* matrix,
  struct matrix_pos __user* upos,
  int write)
{
  uint8_t* byte = NULL;
  struct matrix* target = NULL;

  struct matrix_pos kpos = {0};
  if (copy_from_user(&kpos, upos, sizeof(struct matrix_pos)))
    return -EFAULT;

  spin_lock(&matrix->lock);

  // if write mode, then we use the link
  if (write)
  {
    if (matrix->link)
    {
      target = matrix->link;
      spin_lock(&target->lock);
    }

    spin_unlock(&matrix->lock);
  }
  else
  {
    target = matrix;
  }

  // if we try to write to a matrix without a link then bail out
  if (! target)
    return -EINVAL;

  // check the given row is in bounds
  if (kpos.row < 0 || kpos.row >= target->rows)
    goto err;

  // check the given column is in bounds
  if (kpos.col < 0 || kpos.col >= target->cols)
    goto err;

  /* access the matrix in column major order
   *
   *     [ 1 2 3 ]
   * A = [ 4 5 6 ]
   *     [ 7 8 9 ]
   *
   * 1-D (column-major) A (rows=3, cols=3)= [ 1 4 7 2 5 8 3 6 9]
   * min_row=0 max_row=2, min_col=0, max_col=2
   * row=0,col=0 A[0][0] = (0 * 3) + 0 = A[0] = 1
   * row=1,col=2 A[1][2] = (2 * 3) + 1 = A[7] = 6
   * row=2,col=2 A[2][2] = (2 * 3) + 2 = A[8] = 9
   */

  byte = &target->data[kpos.col * target->cols + kpos.row];

  if (write)
    *byte = kpos.byte;
  else
    kpos.byte = *byte;

  spin_unlock(&target->lock);

  if (copy_to_user(upos, &kpos, sizeof(struct matrix_pos)))
    return -EFAULT;

  return 0;

err:
  spin_unlock(&target->lock);
  return -EINVAL;
}

static int matrix_get_info(struct matrix* matrix, struct matrix_info __user* info)
{
  struct matrix_info kinfo = { 0 };
  kinfo.rows = matrix->rows;
  kinfo.cols = matrix->cols;
  if (copy_to_user(info, &kinfo, sizeof(struct matrix_info)))
    return -EFAULT;
  return 0;
}

static int matrix_set_info(struct matrix* matrix, struct matrix_info __user* info)
{
  struct matrix_info kinfo = {0};
  if (copy_from_user(&kinfo, info, sizeof(struct matrix_info)))
    return -EFAULT;

  if (kinfo.rows < 0 || kinfo.rows > MAX_MATRIX_ROWS)
    return -EINVAL;

  if (kinfo.cols < 0 || kinfo.cols > MAX_MATRIX_COLS)
    return -EINVAL;

  spin_lock(&matrix->lock);

  matrix->rows = kinfo.rows;
  matrix->cols = kinfo.cols;

  if (matrix->data)
    kfree(matrix->data);

  matrix->data = kmalloc(matrix->rows * matrix->cols, GFP_KERNEL);
  if (! matrix->data)
  {
    reset_matrix_locked(matrix);
    spin_unlock(&matrix->lock);
    return -ENOMEM;
  }

  spin_unlock(&matrix->lock);

  return 0;
}

static int matrix_set_name(struct matrix* matrix, char __user* name)
{
  if (copy_from_user(matrix->name, name, sizeof(matrix->name)))
    return -EFAULT;
  return 0;
}

static int matrix_get_name(struct matrix* matrix, char __user* name)
{
  if (copy_to_user(name, matrix->name, sizeof(matrix->name)))
    return -EFAULT;
  return 0;
}

static long matrix_ioctl(
  struct file* file,
  unsigned int code,
  unsigned long arg)
{
  struct matrix* matrix = file->private_data;

  switch (code)
  {
    case IOCTL_MATRIX_SET_NAME:
      return matrix_set_name(matrix, (char __user*) arg);
    case IOCTL_MATRIX_GET_NAME:
      return matrix_get_name(matrix, (char __user*) arg);
    case IOCTL_MATRIX_SET_INFO:
      return matrix_set_info(matrix, (struct matrix_info __user*) arg);
    case IOCTL_MATRIX_GET_INFO:
      return matrix_get_info(matrix, (struct matrix_info __user*) arg);
    case IOCTL_MATRIX_GET_POS:
      return bfs_matrix_pos(matrix, (struct matrix_pos __user*) arg, 0);
    case IOCTL_MATRIX_SET_POS:
      return bfs_matrix_pos(matrix, (struct matrix_pos __user*) arg, 1);
    case IOCTL_MATRIX_DO_LINK:
      return matrix_do_link(matrix, arg);
    default:
      return -EINVAL;
  }
}

struct file_operations const matrix_fops =
{
  .owner          = THIS_MODULE,
  .unlocked_ioctl = matrix_ioctl,
  .open           = matrix_open,
  .release        = matrix_release,
};

static int matrix_do_link(struct matrix* matrix, int ufd)
{
  int error = -EINVAL;

  struct matrix* link = NULL;

  // grab a reference to the file
  struct fd f = fdget(ufd);
  if (! f.file)
    return -EBADF;

  // check that the actual description belongs to a matrix
  link = f.file->private_data;
  if (f.file->f_op != &matrix_fops)
    goto err;

  if (matrix == link)
    goto err;

  if (matrix < link)
  {
    spin_lock(&matrix->lock);
    spin_lock(&link->lock);
  }
  else
  {
    spin_lock(&link->lock);
    spin_lock(&matrix->lock);
  }

  // make a new link
  matrix->link = link;
  link->link = matrix;

  spin_unlock(&matrix->lock);
  spin_unlock(&link->lock);

  error = 0;

err:
  fdput(f);

  return error;
}


static int matrix_open(struct inode* inode, struct file* file)
{
  struct matrix* matrix = NULL;

  // alloc a new matrix
  file->private_data = kzalloc(sizeof(struct matrix), GFP_KERNEL);
  if (! file->private_data)
    return -ENOMEM;

  matrix = file->private_data;

  // intialize the default matrix
  matrix->rows = DEF_MATRIX_ROWS;
  matrix->cols = DEF_MATRIX_COLS;

  strcpy(matrix->name, DEF_MATRIX_NAME);

  matrix->data = kzalloc(matrix->rows * matrix->cols, GFP_KERNEL);
  if (! matrix->data)
  {
    kfree(file->private_data);
    file->private_data = NULL;
    return -ENOMEM;
  }

  // set the current task as owner
  matrix->task = current;

  spin_lock_init(&matrix->lock);

  return 0;
}

static int matrix_release(struct inode* inode, struct file* file)
{
  struct matrix* matrix = file->private_data;

  spin_lock(&matrix->lock);

  // unlink from pair
  if (matrix->link)
    matrix->link->link = NULL;

  // release data
  if (matrix->data)
    kfree(matrix->data);

  spin_unlock(&matrix->lock);

  // release the matrix
  kfree(matrix);

  return 0;
}

struct miscdevice matrix_misc = {
  .fops  = &matrix_fops,
  .minor = MISC_DYNAMIC_MINOR,
  .name  = "bfs_matrix",
};

static int __init misc_init(void)
{
  int error = 0;

  error = misc_register(&matrix_misc);
  if (error < 0)
    pr_err("couldn't register device");

  return error;
}

static void __exit misc_exit(void)
{
  misc_deregister(&matrix_misc);
}

module_init(misc_init);
module_exit(misc_exit);

MODULE_LICENSE("GPL");
