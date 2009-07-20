/*
 * OSXSlightlyBetterAuth.m
 *
 * Created by Michael V. O'Brien on 02/07/2009.
 *
 * This code was written to show how to use
 * AuthorizationExecuteWithPrivileges in a simple and straightforward
 * example.  It is probably not secure, but it gets the job done for
 * demonstration purposes.
 */


#import <Foundation/Foundation.h>
// Add Security.framework to the Xcode project

int main (int argc, const char * argv[]) {
    NSAutoreleasePool * pool = [[NSAutoreleasePool alloc] init];
	
    /*
	 
     OSStatus AuthorizationCreate (
     const AuthorizationRights *rights,
     const AuthorizationEnvironment *environment,
     AuthorizationFlags flags,
     AuthorizationRef *authorization
     );
	 
	 
     OSStatus AuthorizationCopyRights (
     AuthorizationRef authorization,
     const AuthorizationRights *rights,
     const AuthorizationEnvironment *environment,
     AuthorizationFlags flags,
     AuthorizationRights **authorizedRights
     );
	 
	 
     OSStatus AuthorizationExecuteWithPrivileges (
     AuthorizationRef authorization,
     const char *pathToTool,
     AuthorizationFlags options,
     char *const *arguments,
     FILE **communicationsPipe
     );
	 
     */
	
    OSStatus status;  // http://developer.apple.com/documentation/Security/Reference/authorization_ref/Reference/reference.html#//apple_ref/doc/uid/TP30000826-CH4g-CJBEABHG
    AuthorizationRef authorizationRef;
	
    // AuthorizationCreate and pass NULL as the initial AuthorizationRights set so that the AuthorizationRef
    // gets created successfully, and then later call AuthorizationCopyRights to determine or extend the allowable rights.
    // http://developer.apple.com/qa/qa2001/qa1172.html
    status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment, kAuthorizationFlagDefaults, &authorizationRef);
    if (status != errAuthorizationSuccess)
        NSLog(@"Error Creating Initial Authorization: %d", status);
	
    // kAuthorizationRightExecute == "system.privilege.admin"
    AuthorizationItem right = {kAuthorizationRightExecute, 0, NULL, 0};
    AuthorizationRights rights = {1, &right};
    AuthorizationFlags flags = kAuthorizationFlagDefaults |
	kAuthorizationFlagInteractionAllowed |
	kAuthorizationFlagPreAuthorize |
	kAuthorizationFlagExtendRights;
	
    // Call AuthorizationCopyRights to determine or extend the allowable rights.
    status = AuthorizationCopyRights(authorizationRef, &rights, NULL, flags, NULL);
    if (status != errAuthorizationSuccess)
        NSLog(@"Copy Rights Unsuccessful: %d", status);
	
    // EXAMPLE 1: This system tool should work as intended. NOTE: The
    // do-while was used to create scope rather than a function to
    // make this demonstration code read more top-down.
    do {
        NSLog(@"\n\n** %@ **\n\n", @"This command should work.");
        char *tool = "/sbin/dmesg";
        char *args[] = {NULL};
        FILE *pipe = NULL;
		
        status = AuthorizationExecuteWithPrivileges(authorizationRef, tool, kAuthorizationFlagDefaults, args, &pipe);
        if (status != errAuthorizationSuccess)
            NSLog(@"Error: %d", status);
		
        char readBuffer[128];
        if (status == errAuthorizationSuccess) {
            for (;;) {
                int bytesRead = read(fileno(pipe), readBuffer, sizeof(readBuffer));
                if (bytesRead < 1) break;
                write(fileno(stdout), readBuffer, bytesRead);
            }
        }
    } while (0);
	
    // EXAMPLE 2: This system tool, ping, should not work as intended because of the
    // setuid bit.  The ping command was set to "-r-sr-xr-x 1 root wheel" at the time of
    // writing this code.  The ping command must be executed using root privileges to run
    // with an interval that is less than one second.
    do {
        NSLog(@"\n\n** %@ **\n\n", @"This `ping' command should not work.");
        char *tool = "/sbin/ping";
        char *args[] = {"-i", "0.9", "google.com", NULL};
        FILE *pipe = NULL;
		
        // Note that this function respects the setuid bit, if it is set. That is, if the
        // tool you are executing has its setuid bit set and its owner set to foo, the
        // tool will be executed with the user foo's privileges, not root privileges. To
        // ensure that your call to the AuthorizationExecuteWithPrivileges function works
        // as intended, make sure the setuid bit of the tool you wish to execute is
        // cleared before calling AuthorizationExecuteWithPrivileges to execute the tool.
        // http://developer.apple.com/DOCUMENTATION/Security/Reference/authorization_ref/Reference/reference.html#//apple_ref/c/func/AuthorizationExecuteWithPrivileges
        status = AuthorizationExecuteWithPrivileges(authorizationRef, tool, kAuthorizationFlagDefaults, args, &pipe);
        if (status != errAuthorizationSuccess)
            NSLog(@"Error: %d", status);
		
    } while (0);
	
    // The only way to guarantee that a credential acquired when you request a right
    // is not shared with other authorization instances is to destroy the credential.
    // To do so, call the AuthorizationFree function with the flag kAuthorizationFlagDestroyRights.
    // http://developer.apple.com/documentation/Security/Conceptual/authorization_concepts/02authconcepts/chapter_2_section_7.html
    status = AuthorizationFree(authorizationRef, kAuthorizationFlagDestroyRights);
	
    [pool drain];
    return 0;
}
