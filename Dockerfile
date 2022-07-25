FROM node:14.19.0
EXPOSE 8080

WORKDIR /home/nodejs

COPY . /home/nodejs
RUN npm install

CMD ["npm","start"]