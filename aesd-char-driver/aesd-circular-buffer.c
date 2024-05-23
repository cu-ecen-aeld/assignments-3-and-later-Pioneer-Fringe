/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

void aesd_buffer_ptr_inc(uint8_t * bufPtr)
{
    (*bufPtr)++;
    if ((*bufPtr) >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) (*bufPtr) = 0;
}

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    size_t opCharOffset = char_offset;
    uint8_t opOffset = buffer->out_offs;
    
    //if buffer is Full, in_offs and out_offs would start the same
    if (buffer->full)
    {
        if (opCharOffset < buffer->entry[opOffset].size)
        {
            *entry_offset_byte_rtn = opCharOffset;
            return &(buffer->entry[opOffset]);
        }
        else
        {
            opCharOffset -= buffer->entry[opOffset].size;
            aesd_buffer_ptr_inc(&opOffset);
        }
    }
    
    while (opOffset != buffer->in_offs)
    {
        if (opCharOffset < buffer->entry[opOffset].size)
        {
            *entry_offset_byte_rtn = opCharOffset;
            return &(buffer->entry[opOffset]);
        }
        else
        {
            opCharOffset -= buffer->entry[opOffset].size;
            aesd_buffer_ptr_inc(&opOffset);
        }
    }
    
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    if (buffer->full)
    {
        aesd_buffer_ptr_inc(&(buffer->out_offs));
    }
    
    buffer->entry[buffer->in_offs] = *add_entry;
    aesd_buffer_ptr_inc(&(buffer->in_offs));
    if (buffer->in_offs == buffer->out_offs)
        buffer->full = true;
    else
        buffer->full = false;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
