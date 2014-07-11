module DeviseTokenAuth::Concerns::SetUserByToken
  extend ActiveSupport::Concern
  include Devise::Controllers::Helpers
  include Store
  # user auth
  def set_user_by_token
    auth_header = request.headers["Authorization"]

    # missing auth token
    return false unless auth_header

    token      = auth_header[/token=(.*?) /,1]
    uid        = auth_header[/uid=(.*?)$/,1]
    @client_id = auth_header[/client=(.*?) /,1]

    @client_id ||= 'default'

    # mitigate timing attacks by finding by uid instead of auth token
    @user = @current_user = uid && User.find_by_uid(uid)

    if @user && @user.valid_token?(@client_id, token)
      sign_in(:user, @user, store: false, bypass: true)
      Store::Redis.expire("#{@client_id}#{token}", '60')
    else
      @user = @current_user = nil
    end
  end

  def update_auth_header

    if @user && @client_id
      puts "changed"
      # update user's auth token (should happen on each request)
      token                    = SecureRandom.urlsafe_base64(nil, false)
      token_hash               = BCrypt::Password.create(token)

      Store::Redis.hmset("#{@client_id}#{token}", 'user_id', @user.id, 'token',token_hash)
      Store::Redis.expire("#{@client_id}#{token}", '1200')

      # update Authorization response header with new token
      response.headers["Authorization"] = "token=#{token} client=#{@client_id} uid=#{@user.uid}"
    end
  end
end
