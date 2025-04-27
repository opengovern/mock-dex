# app/Dockerfile

# Use an official Node.js runtime as a parent image
# Choose a version compatible with your code (e.g., LTS version like 20)
# Alpine versions are smaller
FROM node:20-alpine

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (or yarn.lock)
# This allows Docker to cache the npm install layer if these files don't change
COPY package*.json ./

# Install app dependencies
# Use --omit=dev if you don't need devDependencies in the final image
RUN npm install --omit=dev

# Bundle app source inside the Docker image
# Copy app.mjs and any other required files (e.g., public assets if any)
COPY . .

# Make port specified by PORT env var available to the outside world
# Defaulting to 3000 if PORT is not set in the environment during build/run
EXPOSE ${PORT:-3000}

# Define the command to run your app using node
# This assumes your main file is app.mjs and package.json has "type": "module"
CMD [ "node", "app.mjs" ]