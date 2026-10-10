#import <AppKit/AppKit.h>
#import <CommonCrypto/CommonDigest.h>
#include <unistd.h>

static void Require(BOOL condition, NSString *message)
{
  if (!condition) @throw [NSException exceptionWithName:@"InstallationError" reason:message ?: @"Installation operation failed." userInfo:nil];
}

static int Run(NSString *program, NSArray<NSString *> *arguments)
{
  NSTask *task = [NSTask new];
  task.executableURL = [NSURL fileURLWithPath:program];
  task.arguments = arguments;
  task.standardOutput = NSFileHandle.fileHandleWithNullDevice;
  task.standardError = NSFileHandle.fileHandleWithNullDevice;
  NSError *error = nil;
  Require([task launchAndReturnError:&error], error.localizedDescription);
  [task waitUntilExit];
  return task.terminationStatus;
}

static NSString *Hash(NSData *data)
{
  Require(data != nil && data.length <= 128 * 1024 * 1024, @"An installation file is missing or too large.");
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
  NSMutableString *result = [NSMutableString new];
  for (unsigned int i = 0; i < sizeof(digest); ++i) [result appendFormat:@"%02x", digest[i]];
  return result;
}

static NSDictionary *Payload(void)
{
  NSBundle *bundle = NSBundle.mainBundle;
  Require(Run(@"/usr/bin/codesign", @[@"--verify", @"--strict", @"--deep", bundle.bundlePath]) == 0,
      @"The installer is damaged. Obtain a new copy of the installation package.");
  NSString *root = [bundle.resourcePath stringByAppendingPathComponent:@"payload"];
  NSData *manifestData = [NSData dataWithContentsOfFile:[root stringByAppendingPathComponent:@"manifest.json"]];
  Require(manifestData != nil, @"The installation manifest is missing.");
  NSDictionary *manifest = [NSJSONSerialization JSONObjectWithData:manifestData options:0 error:NULL];
  Require([manifest isKindOfClass:NSDictionary.class], @"The installation manifest is invalid.");
  NSMutableDictionary *files = [NSMutableDictionary new];
  for (NSString *name in @[@"ida-mcp", @"ida-agent-plugin.dylib"])
  {
    NSData *data = [NSData dataWithContentsOfFile:[root stringByAppendingPathComponent:name]];
    Require([Hash(data) isEqual:manifest[@"sha256"][name]], @"An installation file failed its checksum check.");
    files[name] = data;
  }
  return files;
}

static NSString *AbsoluteDirectory(NSString *path)
{
  path = path.stringByExpandingTildeInPath.stringByStandardizingPath;
  Require(path.isAbsolutePath && ![path isEqual:@"/"], @"Choose an absolute installation directory.");
  return path.stringByResolvingSymlinksInPath;
}

static NSString *ShellQuote(NSString *value)
{
  return [NSString stringWithFormat:@"'%@'", [value stringByReplacingOccurrencesOfString:@"'" withString:@"'\\''"]];
}

static NSDictionary *Install(NSString *idaUser, NSString *gatewayDirectory)
{
  Require(getuid() != 0, @"Run this installer as your normal user, without sudo.");
  NSDictionary *payload = Payload();
  int running = Run(@"/usr/bin/pgrep", @[@"-u", [NSString stringWithFormat:@"%u", getuid()], @"-x", @"ida|idat"]);
  Require(running == 1, @"Close all IDA windows and IDAT processes before installing. No process was stopped.");
  idaUser = AbsoluteDirectory(idaUser);
  gatewayDirectory = AbsoluteDirectory(gatewayDirectory);
  NSString *plugin = [[idaUser stringByAppendingPathComponent:@"plugins"] stringByAppendingPathComponent:@"ida-agent-plugin.dylib"];
  NSString *gateway = [gatewayDirectory stringByAppendingPathComponent:@"ida-mcp"];
  NSString *launcher = [gatewayDirectory stringByAppendingPathComponent:@"Open IDA Agent.command"];
  NSString *command = [NSString stringWithFormat:
      @"#!/bin/zsh\nprint 'Open the local URL below in your browser. Press Ctrl+C to stop.'\nexec %@ -web\n", ShellQuote(gateway)];
  NSArray *destinations = @[plugin, gateway, launcher];
  NSArray *contents = @[payload[@"ida-agent-plugin.dylib"], payload[@"ida-mcp"], [command dataUsingEncoding:NSUTF8StringEncoding]];
  Require([NSSet setWithArray:destinations].count == destinations.count, @"Installation paths overlap.");
  NSFileManager *files = NSFileManager.defaultManager;
  NSString *transaction = NSUUID.UUID.UUIDString;
  NSMutableArray<NSMutableDictionary *> *records = [NSMutableArray new];
  @try
  {
    // Prepare every file before replacing either executable. Keep previous
    // files beside their destination as .backup-UUID, which IDA does not load.
    for (NSUInteger i = 0; i < destinations.count; ++i)
    {
      NSString *destination = destinations[i];
      NSDictionary *existing = [files attributesOfItemAtPath:destination error:NULL];
      Require(existing == nil || [existing[NSFileType] isEqual:NSFileTypeRegular],
          [@"Destination must be a regular file: " stringByAppendingString:destination]);
      NSError *error = nil;
      Require([files createDirectoryAtPath:destination.stringByDeletingLastPathComponent
          withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0700} error:&error], error.localizedDescription);
      NSString *stage = [destination stringByAppendingFormat:@".new-%@", transaction];
      NSMutableDictionary *record = [@{@"destination":destination, @"stage":stage} mutableCopy];
      [records addObject:record];
      Require([contents[i] writeToFile:stage options:NSDataWritingWithoutOverwriting error:&error], error.localizedDescription);
      Require([files setAttributes:@{NSFilePosixPermissions:@0755} ofItemAtPath:stage error:&error], error.localizedDescription);
      Require([Hash([NSData dataWithContentsOfFile:stage]) isEqual:Hash(contents[i])], @"A copied file failed verification.");
    }
    for (NSMutableDictionary *record in records)
    {
      NSString *destination = record[@"destination"];
      NSError *error = nil;
      if ([files fileExistsAtPath:destination])
      {
        NSString *backup = [destination stringByAppendingFormat:@".backup-%@", transaction];
        Require([files moveItemAtPath:destination toPath:backup error:&error], error.localizedDescription);
        record[@"backup"] = backup;
      }
      Require([files moveItemAtPath:record[@"stage"] toPath:destination error:&error], error.localizedDescription);
      record[@"installed"] = @YES;
    }
  }
  @catch (NSException *exception)
  {
    NSMutableArray *restoreErrors = [NSMutableArray new];
    for (NSDictionary *record in records.reverseObjectEnumerator)
    {
      NSError *error = nil;
      if ([record[@"installed"] boolValue] && ![files removeItemAtPath:record[@"destination"] error:&error])
        [restoreErrors addObject:error.localizedDescription];
      if (record[@"backup"] && ![files moveItemAtPath:record[@"backup"] toPath:record[@"destination"] error:&error])
        [restoreErrors addObject:[NSString stringWithFormat:@"Previous file remains at %@", record[@"backup"]]];
      [files removeItemAtPath:record[@"stage"] error:NULL];
    }
    Require(restoreErrors.count == 0, [NSString stringWithFormat:@"%@\n%@", exception.reason, [restoreErrors componentsJoinedByString:@"\n"]]);
    @throw;
  }
  NSMutableArray *backups = [NSMutableArray new];
  for (NSDictionary *record in records) if (record[@"backup"]) [backups addObject:record[@"backup"]];
  return @{@"plugin":plugin, @"gateway":gateway, @"launcher":launcher, @"backups":backups};
}

static NSAlert *Prompt(NSString *idaUser, NSString *gatewayDirectory, NSTextField **pathField)
{
  NSAlert *alert = [NSAlert new];
  alert.messageText = [NSString stringWithFormat:@"Install IDA Agent %@", [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleShortVersionString"]];
  alert.informativeText = [NSString stringWithFormat:
      @"Requires IDA Professional 9.4 and macOS 15 or later.\n\nClose IDA before installing. The plugin is installed into the selected user directory. Existing files are backed up.\n\nMCP gateway:\n%@\n\nIDA user directory (IDAUSR):", gatewayDirectory];
  [alert addButtonWithTitle:@"Install"];
  [alert addButtonWithTitle:@"Cancel"];
  NSTextField *field = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 440, 26)];
  field.stringValue = idaUser;
  alert.accessoryView = field;
  alert.window.title = @"IDA Agent Installer";
  *pathField = field;
  return alert;
}

int main(int argc, const char *argv[])
{
  @autoreleasepool
  {
    BOOL cli = argc > 1 && !(argc == 3 && strcmp(argv[1], "--preview") == 0);
    @try
    {
      if (cli)
      {
        if (argc == 2 && strcmp(argv[1], "--verify-payload") == 0) { Payload(); puts("payload=ok"); return 0; }
        Require(argc == 4 && strcmp(argv[1], "--install") == 0,
            @"Usage: Installer --verify-payload | --install IDA_USER_DIR GATEWAY_DIR");
        NSDictionary *result = Install(@(argv[2]), @(argv[3]));
        NSData *json = [NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
        puts([[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding].UTF8String);
        return 0;
      }
      [NSApplication sharedApplication];
      [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
      [NSApp activate];
      NSString *idaUser = NSProcessInfo.processInfo.environment[@"IDAUSR"];
      if (!idaUser.isAbsolutePath) idaUser = [NSHomeDirectory() stringByAppendingPathComponent:@".idapro"];
      NSString *gatewayDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/ida-agent/bin"];
      NSTextField *field = nil;
      NSAlert *alert = Prompt(idaUser, gatewayDirectory, &field);
      if (argc == 3 && strcmp(argv[1], "--preview") == 0)
      {
        // Optional visual QA; never installs or changes application settings.
        NSString *output = @(argv[2]);
        NSTimer *previewTimer = [NSTimer timerWithTimeInterval:1 repeats:NO block:^(NSTimer *timer) {
          (void)timer;
          NSView *view = alert.window.contentView;
          NSBitmapImageRep *bitmap = [view bitmapImageRepForCachingDisplayInRect:view.bounds];
          [view cacheDisplayInRect:view.bounds toBitmapImageRep:bitmap];
          [[bitmap representationUsingType:NSBitmapImageFileTypePNG properties:@{}] writeToFile:output atomically:YES];
          [NSApp abortModal];
        }];
        [NSRunLoop.mainRunLoop addTimer:previewTimer forMode:NSModalPanelRunLoopMode];
        [alert runModal];
        return 0;
      }
      if ([alert runModal] != NSAlertFirstButtonReturn) return 0;
      NSDictionary *result = Install(field.stringValue, gatewayDirectory);
      NSAlert *complete = [NSAlert new];
      complete.messageText = @"IDA Agent installed";
      complete.informativeText = [NSString stringWithFormat:
          @"Open a database in IDA and choose Edit > Plugins > IDA Agent. Restart MCP clients after upgrading.\n\nGateway: %@\n\nOpen IDA Agent.command starts the local configuration page; open the URL printed in its Terminal window.", result[@"gateway"]];
      [complete addButtonWithTitle:@"Show Installed Files"];
      [complete addButtonWithTitle:@"Done"];
      if ([complete runModal] == NSAlertFirstButtonReturn)
        [NSWorkspace.sharedWorkspace openURL:[NSURL fileURLWithPath:gatewayDirectory]];
      return 0;
    }
    @catch (NSException *exception)
    {
      if (cli) fprintf(stderr, "%s\n", exception.reason.UTF8String);
      else
      {
        NSAlert *alert = [NSAlert new];
        alert.messageText = @"Installation could not finish";
        alert.informativeText = exception.reason;
        [alert runModal];
      }
      return 1;
    }
  }
}
