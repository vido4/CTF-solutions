# Overview
It was a live challenge at OffensiveCon 2023 which was an awesome event. 
It was supposed to be solved live at the venue and was playable all the time throughout the conference, 
but there were a lot of people interested in it so I didn't get a chance to do it live. Fortunately later on organisers shared the files
here (https://twitter.com/bluefrostsec/status/1665999954433720321) so big thanks!
# Challenge
We are given kernel driver C code and qemu setup, as well as a template for our exploit so we do not need to write it from the scratch. 
Things like patching current cred structure to give ourseleves root privilege and all the required offsets are already embeeded in it. 
The only thing that we need to fill are definition of arbitrary read/write primitives and calling the function patching cred structure.

From that we already know that we need to be able to get the arbitrary read/write primitive by abusing the kernel driver.

Driver has some basic operations implemented in `ioctl` handler.
```c
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
```

It essentially handles setting and getting values from allocated NxM sized matrix. The structure of matrix is
```c
struct matrix
 {
     int rows;                 // number of rows in the matrix
     int cols;                 // number of columns in the matrix
     uint8_t* data;            // 1-d backing data (rows x cols size)
     char name[MAX_MATRIX_NAME]; // name of the matrix
     struct matrix* link;      // linked peer
     struct task_struct* task; // owner of the object
     unsigned long lock;          // fine grained locking
 };
```

What immediately stands out is the fact that we have pointer to `task_struct` in the matrix structure 
(if we will be able to leak it, we do not need any other leaked addresses) and the `link` field, 
which probably has to to with `do_link` operation.

In function `bfs_matrix_pos` this link is used - when we are trying to write to the specific matrix we write to its link instead.
For read, the data is read from the matrix normally.
```c
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
```

The driver also handles `open` and `close` so we can create matrixes like normal files with `open` called on device `/dev/bfs_matrix`

Finally we have implementation of `do_link` operation:
```c
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
```

Linking works by binding 2 matrixes - so they point to each other. When closing the matrix, the link is cleared and data freed
```c
   // unlink from pair
   if (matrix->link)
     matrix->link->link = NULL;

   // release data
   if (matrix->data)
     kfree(matrix->data);
```

So directly closing linked matrix will not allow us to reference it from the other matrix for Use-After-Free

# Exploitaition
Keen eyes have probably already noticed, but there are no extra checks or handling for `do_link` operation.
If the matrix is already linked it can be relinked with other matrixes.

We can easily create a situation that will result in Use After Free using 3 matrixes. Basic idea is:
* We open 3 matrixes
* Link matrix A and B
* Link matrix B and C (matrix A still links to B, but B links to C already)
* Free matrix B (link from matrix C will be cleared, but matrix A points to free memory) 

```
|---|     |---|     |---|
| A | ->  | B | <-> | C |
|---|     |---|     |---|
```

With this simple setup, we can write to B->data memory which was already freed (but we cannot read it as links are only used for writes)

Now we need a way for B->data to point to any memory we want - this would allow us to have arbitrary write to any memory.

For that, the functionality which i did not describe before `matrix_set_info` comes in handy. It allows us to resize the matrix being used,
by freeing the previous matrix and allocating a new one, basically doing 
```c
   matrix->rows = kinfo.rows;
   matrix->cols = kinfo.cols;

   if (matrix->data)
     kfree(matrix->data);

   matrix->data = kmalloc(matrix->rows * matrix->cols, GFP_KERNEL);
```

In Linux kernel the most recently freed memory will be at the top of freelist and memory will be reused on next similar-sized allocation.

So before freeing 2nd matrix (Matrix B above), we set its matrix size to match `sizeof(matrix)` 
(at least so it will be in the same kmalloc slab)

Then after closing 2nd matrix freelist looks like this
```
|kmalloc-64 slab|
(NEWEST -> OLDER)
freed B matrix -> freed B.data
```

At this point - I used `matrix_set_info` on matrix A ,to resize it to `sizeof(matrix)`, so we can get arbitrary read. 
Newly allocated `A->data` should overlap the `freed B matrix` shown above. Simply be reading data from `A` matrix we get necessary leaks.

So summing it up - so far we can do
* Allocate matrix A,B,C
* Link A,B
* Link B,C
* Resize B->data to match sizeof(matrix)
* Close B
* Resize A->data to match sizeof(matrix)
* Read A->data for leaking B matrix data

With that we can leak current task_struct pointer as well as heap location of matrix C (by reading link field)

Now we need to setup proper write. Right now the freelist is
```
|kmalloc-64 slab|
(NEWEST -> OLDER)
freed B.data
```
So the next allocated memory will overlap previously freed `B->data` ptr. When writing to matrix A, 
in reality we write to `B->data` in our setup. So the plan is - allocate new matrix D - so when we write to matrix A, it will change the
internal fields of matrix D. For arbitrary write, we would then write to matrix A (for overriding data) and then write to matrix linked with D.
So we need new matrix E, linked with D as well.

The whole setup is then as follows:
* Allocate matrix A,B,C
* Link A,B
* Link B,C
* Resize B->data to match sizeof(matrix)
* Close B
* Resize A->data to match sizeof(matrix)
* Allocate D,E
* Link A,E

```
    ->data
  -----------
  |         |
  |         v
|---|     |---|     |---|       |---|     |---|
| A | ->  | B*| <-> | C |       | D | <-> | E |
|---|     |---|     |---|       |---|     |---|
            |                     ^
            |                     |
            ----------------------|
                    ->data
```

While B* matrix is freed (memory regions it used are overlapped by A->data and D).

Performing arbitrary read and write is done by:
* Write arbitrary address to A (which essentially will overwrite D matrix data pointer)
* Read data from matrix D for arbitrary read
* Write data to matrix E (linked with D) for arbitary write.

With that we have arbitrary read/write primitives set and we can just call patch_creds for getting root privileges.
Whole resulting exploit in in `exploit.c` I did not provide all kernel file - for testing it download files through the twitter link
above or directly from https://static.bluefrostsecurity.de/files/lab/bfsmatrix_offensivecon2023.tgz
