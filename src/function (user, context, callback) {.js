function (user, context, callback) {
    // check if this request is for the sensitive application
    if(context.clientID === 'i1jnSxa9N7BzAJ3BqqPQo7rwjQ0zdjO1') 
  
    //check for absolute session timeout
    if(context.authentication && context.authentication.methods) {
      let allowedSessionLifetime = 180; //seconds
      let leeway = 2; //seconds
    
          //Check if authn method match pwd or social connections
        const authMethod = context.authentication.methods.find(
          (method) => {
            return (method.name === 'pwd' || method.name === 'federated');
          }
        );
        console.log('[sase] auth method is:', authMethod);
  
        if (!authMethod) {
          console.log('[sase] skipping rule - invalid auth method');
          return callback(null, user, context);
        }
  
        var authnTimeStamp = authMethod.timestamp;
        console.log('[sase] user authenticated at: ', authnTimeStamp);
  
        var currentDate = new Date();
        var currentEpochTimeStamp = currentDate.getTime();
        console.log('[sase] current time is:', currentEpochTimeStamp);
  
        var currentSessionAge = Math.trunc(((currentEpochTimeStamp - authnTimeStamp)/1000));
        console.log('[sase] currentSessionAge is:', currentSessionAge, ' seconds');
  
        if(currentSessionAge + leeway < allowedSessionLifetime || context.request.query.prompt === 'login') {
          console.log('[sase] session is fresh - allow login');
            
          if(context.sso.current_clients && context.sso.current_clients.includes(context.clientID)) {
              return callback(new UnauthorizedError("x_login_required_silent_auth_not_allowed"));    
          }
  
          callback(null, user, context);
        } else {
            console.log('[sase] must re-authenticate');
            return callback(new UnauthorizedError("x_login_required_absolute_timeout"));
        }
    }
    callback(null, user, context);
  }