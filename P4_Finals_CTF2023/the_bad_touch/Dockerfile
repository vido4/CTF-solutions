FROM patryk4815/nsjail:23.04

WORKDIR /home/pwn
COPY bad entrypoint.sh ./ 
COPY flag.txt ./

EXPOSE 4000/tcp
CMD /home/pwn/entrypoint.sh
