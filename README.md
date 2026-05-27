git clone https://github.com/EGlezPlz/soc-lab.git
cd soc-lab
cp soc-lab/backend/.env.example soc-lab/backend/.env
# editar .env con las credenciales del doc privado
./soc-lab/start.sh --build
