#ifndef _PORTABLE_SNPRINTF_H_
# define _PORTABLE_SNPRINTF_H_

extern int snprintf (
  char *,
  size_t,
  const char *,                 /*args */
  ...
);
extern int vsnprintf (
  char *,
  size_t,
  const char *,
  va_list
);

#endif
