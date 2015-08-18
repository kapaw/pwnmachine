# -*- mode: ruby -*-
# vi: set ft=ruby :


$install = <<EOF
#Install packages
sudo apt-get -y update
sudo apt-get -y upgrade
sudo apt-get -y install git python-pip python-dev build-essential \
    python-software-properties gdb curl vim exuberant-ctags pyflakes \
    cmake clang-3.5 software-properties-common

#Install pwntools + dependencies
git clone https://github.com/Gallopsled/pwntools.git
cd pwntools
sudo python setup.py install
cd /home/vagrant

#Install many binutils
sudo apt-add-repository --yes ppa:pwntools/binutils
sudo apt-get update
sudo apt-get install binutils-{arm,i386,mips}-linux-gnu

#Install voltron (https://github.com/snare/voltron)
git clone https://github.com/snare/voltron.git
cat > .gdbinit <<GDB_EOF
set follow-fork-mode child
set disassembly-flavor intel

source /home/vagrant/voltron/dbgentry.py
voltron init
GDB_EOF
cd voltron
sudo python setup.py install
cd /home/vagrant

#Configure vim
mkdir -p .vim/autoload .vim/bundle
ctags-exuberant --fields=+S --sort=yes -f /home/vagrant/.vim/systags   -R /usr/include 2>/dev/null
curl -LSso .vim/autoload/pathogen.vim https://tpo.pe/pathogen.vim
git clone https://github.com/SirVer/ultisnips.git .vim/bundle/ultisnips
git clone git://github.com/honza/vim-snippets.git .vim/bundle/vim-snippets
git clone https://github.com/tpope/vim-fugitive.git .vim/bundle/vim-fugitive
git clone https://github.com/kevinw/pyflakes-vim.git .vim/bundle/pyflakes-vim
git clone https://github.com/scrooloose/syntastic.git .vim/bundle/syntastic
git clone https://github.com/Valloric/YouCompleteMe.git .vim/bundle/YouCompleteMe
git clone https://github.com/bling/vim-airline.git .vim/bundle/vim-airline
git clone https://github.com/kien/ctrlp.vim.git .vim/bundle/ctrlp.vim
git clone https://github.com/ervandew/supertab.git .vim/bundle/supertab.vim

cd .vim/bundle/YouCompleteMe
git submodule update --init --recursive
./install.sh --clang-completer
cd /home/vagrant


cat > .vim/vimrc <<VIM_EOF
execute pathogen#infect()

syntax on
colo elflord
set hlsearch
set incsearch
set expandtab
set tabstop=4
set shiftwidth=4
set ignorecase
set smartcase
set number
set si
filetype plugin indent on

autocmd FileType java map <F8> :!ant<CR>
autocmd FileType java map <F9> :!ant run<CR>
autocmd FileType cpp set tags+=~/.vim/systags
autocmd FileType cpp set omnifunc=ccomplete#Complete
autocmd FileType c set tags+=~/.vim/systags
autocmd FileType c set omnifunc=ccomplete#Complete
autocmd FileType php set omnifunc=phpcomplete#CompletePHP
autocmd FileType xml set omnifunc=xmlcomplete#CompleteXML
autocmd FileType html set omnifunc=htmlcomplete#CompleteTags
map <F8> :make<CR>
map <F9> :make<CR>

"YCM
let g:ycm_key_list_select_completion = ['<C-n>', '<Down>']
let g:ycm_key_list_previous_completion = ['<C-p>', '<Up>']
let g:SuperTabDefaultCompletionType = '<C-n>'

"UltiSnips
let UltiSnipsEditSplit="vertical"
let g:UltiSnipsExpandTrigger="<tab>"
let g:UltiSnipsJumpForwardTrigger="<tab>"
let g:UltiSnipsJumpBackwardTrigger="<s-tab>"

VIM_EOF
ln -s .vim/vimrc .vimrc
sudo chown -R vagrant.vagrant /home/vagrant


EOF

Vagrant.configure(2) do |config|
    config.vm.box = "puphpet/ubuntu1404-x64"
    config.vm.provision "shell", inline: $install
end
