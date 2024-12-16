FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /code

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Copy project
COPY . .

# Expose port
EXPOSE 8000

CMD ["bash", "-c", "python manage.py makemigrations --noinput && \
python manage.py migrate --noinput && \
gunicorn --bind 0.0.0.0:8000 iot_parser.wsgi:application"]