/*
** aout.c for chpax
**
** The PaX project : http://pax.grsecurity.net/
**
*/
#include "chpax.h"


unsigned long	get_flags_aout()
{
  return (N_FLAGS(header_aout));
}

void		put_flags_aout(unsigned long flags)
{
  N_SET_FLAGS(header_aout, flags & ~HF_PAX_RANDMMAP);
}
