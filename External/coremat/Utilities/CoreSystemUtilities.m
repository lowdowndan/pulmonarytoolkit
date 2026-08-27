classdef CoreSystemUtilities
    % CoreSystemUtilities. Utility functions relating to the hardware or operating system.
    %
    %
    %     Licence
    %     -------
    %     Part of CoreMat. https://github.com/tomdoel/coremat
    %     Author: Tom Doel, 2013.  www.tomdoel.com
    %     Distributed under the MIT licence. Please see website for details.
    %    
    
    methods (Static)

        function uid = GenerateUid()
            % Creates a random unique identifier
            
            % On unix systems, if java is not running we can use the system
            % command
            if isunix && ~usejava('jvm')
                [status, uid] = system('uuidgen');
                if status ~= 0
                    error('Failure running uuidgen');
                end
            else
                uid = char(java.util.UUID.randomUUID);
            end
        end
        
        function hash = StringToHash(string)
            % Performs an SHA hash on a string
            persistent messageDigest
            if usejava('jvm')
                if isempty(messageDigest)
                    messageDigest = java.security.MessageDigest.getInstance('SHA-256');
                end
                hash = sprintf('%2.2x', typecast(messageDigest.digest(uint8(string)), 'uint8')');
            else
                % Java-free path (deployed apps: MATLAB Runtime no longer
                % ships a JVM). Pure-MATLAB SHA-256 producing the SAME
                % digest as the Java path, so caches stay compatible.
                hash = CoreSystemUtilities.Sha256NoJava(uint8(string));
            end
        end

        function hash = Sha256NoJava(bytes)
            % Pure-MATLAB SHA-256 (FIPS 180-4). Digest-identical to
            % java.security.MessageDigest('SHA-256').
            K = uint32([ ...
                1116352408 1899447441 3049323471 3921009573  961987163 1508970993 2453635748 2870763221 ...
                3624381080  310598401  607225278 1426881987 1925078388 2162078206 2614888103 3248222580 ...
                3835390401 4022224774  264347078  604807628  770255983 1249150122 1555081692 1996064986 ...
                2554220882 2821834349 2952996808 3210313671 3336571891 3584528711  113926993  338241895 ...
                 666307205  773529912 1294757372 1396182291 1695183700 1986661051 2177026350 2456956037 ...
                2730485921 2820302411 3259730800 3345764771 3516065817 3600352804 4094571909  275423344 ...
                 430227734  506948616  659060556  883997877  958139571 1322822218 1537002063 1747873779 ...
                1955562222 2024104815 2227730452 2361852424 2428436474 2756734187 3204031479 3329325298]);
            H = uint32([1779033703 3144134277 1013904242 2773480762 ...
                        1359893119 2600822924  528734635 1541459225]);
            msg = uint8(bytes(:))';
            lenBits = uint64(numel(msg)) * 8;
            padLen = mod(55 - numel(msg), 64);
            msg = [msg, uint8(128), zeros(1, padLen, 'uint8'), ...
                   typecast(swapbytes(lenBits), 'uint8')];
            add32 = @(varargin) uint32(mod(sum(cellfun(@double, varargin)), 4294967296));
            rotr  = @(x, n) bitor(bitshift(x, -n), bitshift(x, 32 - n));
            for iBlock = 1:numel(msg)/64
                block = msg((iBlock-1)*64 + (1:64));
                W = zeros(1, 64, 'uint32');
                W(1:16) = swapbytes(typecast(block, 'uint32'));
                for t = 17:64
                    s0 = bitxor(bitxor(rotr(W(t-15), 7), rotr(W(t-15), 18)), bitshift(W(t-15), -3));
                    s1 = bitxor(bitxor(rotr(W(t-2), 17), rotr(W(t-2), 19)), bitshift(W(t-2), -10));
                    W(t) = add32(W(t-16), s0, W(t-7), s1);
                end
                a=H(1); b=H(2); c=H(3); d=H(4); e=H(5); f=H(6); g=H(7); h=H(8);
                for t = 1:64
                    S1 = bitxor(bitxor(rotr(e, 6), rotr(e, 11)), rotr(e, 25));
                    ch = bitxor(bitand(e, f), bitand(bitcmp(e), g));
                    temp1 = add32(h, S1, ch, K(t), W(t));
                    S0 = bitxor(bitxor(rotr(a, 2), rotr(a, 13)), rotr(a, 22));
                    maj = bitxor(bitxor(bitand(a, b), bitand(a, c)), bitand(b, c));
                    temp2 = add32(S0, maj);
                    h=g; g=f; f=e; e=add32(d, temp1);
                    d=c; c=b; b=a; a=add32(temp1, temp2);
                end
                H = [add32(H(1),a) add32(H(2),b) add32(H(3),c) add32(H(4),d) ...
                     add32(H(5),e) add32(H(6),f) add32(H(7),g) add32(H(8),h)];
            end
            hash = sprintf('%08x', H);
        end
        
        function dimensions = GetMonitorDimensions()
            % Gets the resolution of the screen
            
            if usejava('jvm')
                d = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
                dimensions = [d.width, d.height];
            else
                dimensions = get(0, 'ScreenSize');
                dimensions = dimensions(3:4);
            end
        end
        
        function bytes_in_type = GetBytesInType(type_string)
            % Returns the number of bytes in the given Matlab type
            
            switch type_string
                case {'int8', 'uint8'}
                    bytes_in_type = 1;
                case {'uint16', 'int16'}
                    bytes_in_type = 2;
                case {'uint32', 'int32'}
                    bytes_in_type = 4;
                case {'uint64', 'int64'}
                    bytes_in_type = 8;
                otherwise
                    error('CoreSystemUtilities:GetBytesInType', 'Unknown number type');
            end
        end
        
        function computer_endian = GetComputerEndian()
            % Returns an enumeration for the endian of this computer
            
            [~, ~, computer_endian_str] = computer;
            
            switch computer_endian_str
                case 'B'
                    computer_endian = CoreEndian.BigEndian;
                case 'L'
                    computer_endian = CoreEndian.LittleEndian;
                otherwise
                    error('CoreSystemUtilities:GetComputerEndian', 'Unknown endian');
            end
        end

        function DeleteIfValidObject(object_handle)
            % Deletes an object
            
            if ~isempty(object_handle)
                if isvalid(object_handle)
                    delete(object_handle);
                end
            end
        end
        
        function DeleteIfGraphicsHandle(handle)
            % Removes a graphics handle
            
            if ishandle(handle)
                delete(handle);
            end
        end
        
        function colormap = BackwardsCompatibilityColormap()
            % Returns a colormap which replicates the default colormap from
            % Matlab versions pre-hg2
            
            old_colormap = [0 0 1; 0 0.5 0; 1 0 0; 0 0.75 0.75; 0.75 0 0.75; 0.75 0.75 0; 0.25 0.25 0.25];
            colormap = repmat(old_colormap, [9, 1]);
            colormap = [colormap; [0 0 1]];
        end
        
        function [major_version, minor_version] = GetMatlabVersion()
            % Returns the major and minor version numbers of Matlab
            
            [matlab_version, ~] = version;
            version_matrix = sscanf(matlab_version, '%d.%d.%d.%d');
            major_version = version_matrix(1);
            minor_version = version_matrix(2);
        end
        
        function toolbox_installed = IsImageProcessingToolboxInstalled()
            % Returns true if the Matlab image processing toolbox is
            % installed
            
            matlab_version = ver;
            toolbox_installed = any(strcmp('Image Processing Toolbox', {matlab_version.Name}));
        end

        function toolbox_licensed = IsImageProcessingToolboxLicensed()
            % Returns true if the Matlab image processing toolbox has a valid licence
            
            [error_code, error_message] = license('checkout', 'image_toolbox');
            toolbox_licensed = error_code == 1;
        end
        
        function path_to_executable = FindFirstExecutableOnPath(executable_name)
            % Returns the path of the first executable found on the system
            % path with the specified name

            if ispc
                [status, path_to_executable] = system(['where ' executable_name]);
            else
                [status, path_to_executable] = system(['which ' executable_name]);
            end
            
            if status == 0
                % Extract out the first executable, if more than one are
                % returned (which can happen with where on Windows)
                path_to_executable = CoreTextUtilities.RemoveNonprintableCharactersAndStrip(strtok(path_to_executable, char(13)));
            else
                path_to_executable = [];
            end
        end
    end
end

