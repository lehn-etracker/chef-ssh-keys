if node['ssh_keys']
  node['ssh_keys'].each do |node_user, bag_users|
    next unless node_user
    next unless bag_users

    # Getting node user data
    user = node['etc']['passwd'][node_user]

    # Defaults for new user
    user = {'uid' => node_user, 'gid' => node_user, 'dir' => "/home/#{node_user}"} unless user

    if user and user['dir'] and user['dir'] != "/dev/null"
      # Preparing SSH keys
      ssh_keys = []
      bag_users_list = []

      if bag_users.kind_of?(String)
        bag_users_list = Array(bag_users)
      elsif bag_users.kind_of?(Array)
        bag_users_list = bag_users
      else
        bag_users_list = bag_users['users']
      end

      Array(bag_users_list).each do |bag_user|
        data = node['ssh_keys_use_encrypted_data_bag'] ?
          Chef::EncryptedDataBagItem.load('users', bag_user) :
          data_bag_item('users', bag_user)

        if data and data['ssh_keys']
          ssh_keys += Array(data['ssh_keys']).map{|x| (data['ssh_options'] ? data['ssh_options']+' '+x : x)}
        end
      end

      if not bag_users.kind_of?(String) and not bag_users.kind_of?(Array) and bag_users['groups'] != nil
        Array(bag_users['groups']).each do |group_name|
          if not Chef::Config[:solo]
            search(:users, 'groups:' + group_name) do |search_user|
              ssh_keys += Array(search_user['ssh_keys']).map{|x| (search_user['ssh_options'] ? search_user['ssh_options']+' '+x : x)}
            end
          else
            Chef::Log.warn("[ssh-keys] This recipe uses search for users detection by groups. Chef Solo does not support search.")
          end
        end
      end

      # Saving SSH keys
      if ssh_keys.length > 0
        home_dir = user['dir']

        if node['ssh_keys_skip_missing_home'] and not File.exists?(home_dir)
          next
        end

        authorized_keys_file = "#{home_dir}/.ssh/authorized_keys"

        if node['ssh_keys_keep_existing'] && File.exist?(authorized_keys_file)
          Chef::Log.info("Keep authorized keys from: #{authorized_keys_file}")

          valid_key_regexp=%r{
              ^((?<ssh_options>(command=|          # match valid ssh-option
                                tunnel=|
                                no-pty|
                                environment=|
                                from=|
                                tunnel=|
                                permitopen=|
                                no-port-forwarding)
                ([^\s,]*|"[^"]*")[,]*)*\s|)       # match options values either with no space, or surrounded by "
               (?<ssh_key>(ssh-dss|               # match ssh key in any format
                           ssh-rsa|
                           ssh-ed25519|
                           ecdsa-sha2-nistp256|
                           ecdsa-sha2-nistp384|
                           ecdsa-sha2-nistp521)
                \s([^\s]*)
               )
               (.*)  # match remainder, e.g. comments
          }x

          # Loading existing keys
          File.open(authorized_keys_file).each do |line|
            valid_key=valid_key_regexp.match(line)
            if valid_key && !ssh_keys.find_index{|x| x.include?(valid_key[:ssh_key])}  # Only load valid keys and not previously loaded ones, ignoring options
              ssh_keys += Array(line.delete "\n")
              Chef::Log.debug("[ssh-keys] Keeping key from #{authorized_keys_file}: #{line}")
            else
              Chef::Log.debug("[ssh-keys] Dropping key from #{authorized_keys_file}: #{line}")
            end
          end
          ssh_keys.uniq!
        else
          # Creating ".ssh" directory
          if node['ssh_keys_create_missing_home']
            directory "#{home_dir}/.ssh" do
              owner user['uid']
              group user['gid'] || user['uid']
              mode "0700"
              recursive true
            end
          else
            directory "#{home_dir}/.ssh" do
              owner user['uid']
              group user['gid'] || user['uid']
              mode "0700"
            end
          end
        end

        # local variable to determine if authorized_keys file ownership should 
        # be managed too
        ssh_local_system_supports_chown = true
        if node.include?('packages') and 
		node['packages'].include?('proxmox-ve') and user['uid'] == 0
          ssh_local_system_supports_chown = false
        end
        
        # Creating "authorized_keys"
        if ssh_local_system_supports_chown == true
          # authorized_keys file ownership supported
          template authorized_keys_file do
            source "authorized_keys.erb"
            owner user['uid']
            group user['gid'] || user['uid']
            mode "0600"
            variables :ssh_keys => ssh_keys
          end
        else
          # authorized_keys file ownership not supported
          template authorized_keys_file do
            source "authorized_keys.erb"
            mode "0600"
            variables :ssh_keys => ssh_keys
          end
        end
      end
    end
  end
end
