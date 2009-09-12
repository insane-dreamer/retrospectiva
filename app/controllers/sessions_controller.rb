class SessionsController < ApplicationController
  verify :params => [:username], :xhr => true, :only => :secure

  prepend_before_filter :reset_session, :only => [:destroy]
  before_filter :verify_secure_authentication, :only => [:secure]
  skip_filter :store_back_to_path

  def new
    login_by_http_auth if HTTP_AUTH_ONLY
    render :action => 'logged_in' unless User.current.public?
  end

  def create
    session[:user_id] = nil
    user = User.authenticate(params[:user] || {})
    if user
      successful_login(user)
    else
      failed_login _('Login was not successful. Invalid username or password.')
    end
  end

  def destroy
  end

  def secure
    user = User.active.find_by_username params[:username]
    user ? render(:text => user.salt) : render(:nothing => true)
  end
  
  protected
    
    def successful_login(user, message = nil)
      back_to = session[:back_to].present? ? session[:back_to] : root_path
      message ||= _('Login was successful.')

      session[:user_id] = user.id
      flash[:notice] = message
      redirect_to back_to
    end

    def failed_login(message)
      flash[:error] = message
      redirect_to login_path
    end
        
    def verify_secure_authentication
      unless RetroCM[:general][:user_management][:secure_auth]
        render :nothing => true 
      end
    end

    def login_by_http_auth
      # Apache sets the secure HTTP_X_REMOTE_USER if a user has logged in using Digest authentication 
      # or REMOTE_USER if on a LAN with NTLM
      # set HTTP_AUTH_ONLY in config.rb
      auth = (request.env['HTTP_X_REMOTE_USER'] || request.env['REMOTE_USER'])
      user = User.find_by_username(auth)
      if user
        successful_login(user, "Welcome, #{auth}.")
      else
        flash[:notice] = "No user #{auth} found. Accessing as guest."
        redirect_to home_path
      end
    end

end
