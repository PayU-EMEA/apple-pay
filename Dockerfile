FROM php:8.0-cli

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# OpenSSL extension is already included in PHP by default
# No additional PHP extensions needed for this project

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /app

# Copy composer files
COPY composer.json composer.lock* ./

# Install PHP dependencies
RUN composer install --no-scripts --no-autoloader --prefer-dist

# Copy project files
COPY . .

# Generate autoloader
RUN composer dump-autoload --optimize

# Default command
CMD ["php", "-a"]
