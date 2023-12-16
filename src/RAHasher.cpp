// RAHasher.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Git.h"
#include "Hash.h"
#include "Util.h"

#include <rcheevos/include/rc_hash.h>

#include <memory>
#include <string.h>

#ifdef HAVE_CHD
void rc_hash_init_chd_cdreader(); /* in HashCHD.cpp */
#endif

static std::string g_systemDir = ".";

static void usage(const char* appname)
{
  printf("RAHasher %s\n====================\n", git::getReleaseVersion());

  printf("Usage: %s [-v] [s systempath] systemid filepath\n", util::fileName(appname).c_str());
  printf("\n");
  printf("  -v             (optional) enables verbose messages for debugging\n");
  printf("  -s systempath  (optional) specifies where supplementary files are stored (typically a path to RetroArch/system)\n");
  printf("  systemid       specifies the system id associated to the game (which hash algorithm to use)\n");
  printf("  filepath       specifies the path to the game file\n");
}

class StdErrLogger : public Logger
{
public:
  void log(enum retro_log_level level, const char* line, size_t length) override
  {
    // ignore non-errors unless they're coming from the hashing code
    if (level != RETRO_LOG_ERROR && strncmp(line, "[HASH]", 6) != 0)
      return;

    // don't print the category
    while (*line && *line != ']')
    {
      ++line;
      --length;
    }
    while (*line == ']' || *line == ' ')
    {
      ++line;
      --length;
    }

    ::fwrite(line, length, 1, stderr);
    ::fprintf(stderr, "\n");
  }
};

static std::unique_ptr<StdErrLogger> logger;

static void rhash_log(const char* message)
{
  printf("%s\n", message);
}

static void rhash_log_error(const char* message)
{
  fprintf(stderr, "%s\n", message);
}

static void* rhash_file_open(const char* path)
{
  return util::openFile(logger.get(), path, "rb");
}

static int rhash_3ds_lookup_cia_normal_key(uint8_t index, uint8_t key[16])
{
  char scan[16];
  size_t scan_len;
  char buffer[128];
  char* line;
  int result = 0;

  FILE* fp = util::openFile(logger.get(), g_systemDir + "/aes_keys.txt", "r");
  if (!fp)
    return 0;

  scan_len = snprintf(scan, sizeof(scan), "common%u=", index);

  while (line = fgets(buffer, sizeof(buffer), fp))
  {
    if (memcmp(line, scan, scan_len) == 0)
    {
      int index;
      line += scan_len;
      scan[2] = '\0';

      for (index = 0; index < 16; ++index)
      {
        scan[0] = line[0];
        scan[1] = line[1];

        key[index] = (uint8_t) strtol(scan, NULL, 16);
        line += 2;
      }

      result = 1;
      break;
    }
  }

  fclose(fp);
  return result;
}

#define RC_CONSOLE_MAX 90

int main(int argc, char* argv[])
{
  int consoleId = 0;
  std::string file;
  char hash[33];
  int result = 1;
  int argi = 1;

  while (argv[argi][0] == '-')
  {
    if (strcmp(argv[argi], "-v") == 0)
    {
      rc_hash_init_verbose_message_callback(rhash_log);
      ++argi;
    }
    else if (strcmp(argv[argi], "-s") == 0)
    {
      g_systemDir = argv[++argi];
      ++argi;
    }
  }

  if (argi + 2 <= argc)
  {
    consoleId = atoi(argv[argi]);
    file = argv[argi + 1];
  }

  if (consoleId != 0 && !file.empty())
  {
    file = util::fullPath(file);

    logger.reset(new StdErrLogger);

    rc_hash_init_error_message_callback(rhash_log_error);

    std::string ext = util::extension(file);
    if (consoleId != RC_CONSOLE_ARCADE && consoleId <= RC_CONSOLE_MAX && ext.length() == 4 &&
      tolower(ext[1]) == 'z' && tolower(ext[2]) == 'i' && tolower(ext[3]) == 'p')
    {
      std::string unzippedFilename;
      size_t size;
      void* data = util::loadZippedFile(logger.get(), file, &size, unzippedFilename);
      if (data)
      {
        if (rc_hash_generate_from_buffer(hash, consoleId, (uint8_t*)data, size))
          printf("%s\n", hash);

        free(data);
      }
    }
    else
    {
      /* register a custom file_open handler for unicode support. use the default implementation for the other methods */
      struct rc_hash_filereader filereader;
      memset(&filereader, 0, sizeof(filereader));
      filereader.open = rhash_file_open;
      rc_hash_init_custom_filereader(&filereader);

      if (ext.length() == 4 && tolower(ext[1]) == 'c' && tolower(ext[2]) == 'h' && tolower(ext[3]) == 'd')
      {
#ifdef HAVE_CHD
        rc_hash_init_chd_cdreader();
#else
        printf("CHD not supported without HAVE_CHD compile flag\n");
        return 0;
#endif
      }
      else
      {
        rc_hash_init_default_cdreader();
      }

      if (consoleId == RC_CONSOLE_NINTENDO_3DS)
        rc_hash_init_3ds_cia_normal_key_callback(rhash_3ds_lookup_cia_normal_key);

      if (consoleId > RC_CONSOLE_MAX)
      {
        rc_hash_iterator iterator;
        rc_hash_initialize_iterator(&iterator, file.c_str(), NULL, 0);
        while (rc_hash_iterate(hash, &iterator))
          printf("%s\n", hash);
        rc_hash_destroy_iterator(&iterator);
      }
      else
      {
        if (rc_hash_generate_from_file(hash, consoleId, file.c_str()))
          printf("%s\n", hash);
      }
    }

    return result;
  }

  usage(argv[0]);
  return 1;
}
