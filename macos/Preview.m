#import <Cocoa/Cocoa.h>
#import <ScreenSaver/ScreenSaver.h>
@interface PreviewDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate>
@property(nonatomic, strong) NSWindow *window;
@property(nonatomic, strong) ScreenSaverView *view;
@property(nonatomic, strong) NSTimer *timer;
@end
@implementation PreviewDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    NSString *path=[NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"Contents/Resources/ThreatAtlasSOC.saver"];
    NSBundle *bundle=[NSBundle bundleWithPath:path];NSError *error=nil;
    if (![bundle loadAndReturnError:&error]) {NSLog(@"%@",error);[NSApp terminate:nil];return;}
    self.view=[[[bundle principalClass] alloc] initWithFrame:NSMakeRect(0,0,1200,750) isPreview:NO];
    self.window=[[NSWindow alloc] initWithContentRect:NSMakeRect(100,100,1200,750) styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskResizable|NSWindowStyleMaskMiniaturizable backing:NSBackingStoreBuffered defer:NO];
    self.window.releasedWhenClosed=NO;
    self.window.delegate=self;
    self.window.title=@"Threat Atlas — Live SOC Preview";self.window.contentView=self.view;
    NSMenu *menu=[NSMenu new];NSMenuItem *item=[NSMenuItem new];[menu addItem:item];NSMenu *appMenu=[NSMenu new];[appMenu addItemWithTitle:@"Enable automatic updates" action:@selector(enableUpdates:) keyEquivalent:@""];[appMenu addItemWithTitle:@"Disable automatic updates" action:@selector(disableUpdates:) keyEquivalent:@""];[appMenu addItemWithTitle:@"Quit Threat Atlas" action:@selector(terminate:) keyEquivalent:@"q"];item.submenu=appMenu;NSApp.mainMenu=menu;
    [self.window center];[self.window makeKeyAndOrderFront:nil];[NSApp activateIgnoringOtherApps:YES];
    [self.view startAnimation];
    self.timer=[NSTimer scheduledTimerWithTimeInterval:0.05 target:self.view selector:@selector(animateOneFrame) userInfo:nil repeats:YES];
}
- (void)updateMode:(NSString *)mode {
    NSTask *task=[NSTask new];task.executableURL=[NSBundle.mainBundle.bundleURL URLByAppendingPathComponent:@"Contents/MacOS/ThreatAtlasUpdater"];task.arguments=@[mode];
    NSError *error=nil;BOOL launched=[task launchAndReturnError:&error];if(launched)[task waitUntilExit];
    NSAlert *alert=[NSAlert new];alert.messageText=launched&&task.terminationStatus==0?@"Update preference saved":@"Could not change update preference";
    alert.informativeText=launched&&task.terminationStatus==0?@"Updates use stable, trusted releases. See ~/Library/Logs/ThreatAtlas-update.log for status.":@"Automatic updates require a Developer ID signed release and a per-user installation. See ~/Library/Logs/ThreatAtlas-update.log for details.";[alert runModal];
}
- (void)enableUpdates:(id)sender {[self updateMode:@"--enable"];}
- (void)disableUpdates:(id)sender {[self updateMode:@"--disable"];}
- (void)windowWillClose:(NSNotification *)notification {[NSApp terminate:nil];}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {return YES;}
- (void)applicationWillTerminate:(NSNotification *)notification {[self.timer invalidate];[self.view stopAnimation];}
@end
int main(){@autoreleasepool {NSApplication *app=[NSApplication sharedApplication];[app setActivationPolicy:NSApplicationActivationPolicyRegular];PreviewDelegate *delegate=[PreviewDelegate new];app.delegate=delegate;[app run];}return 0;}
