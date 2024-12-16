from django.http import JsonResponse

class Custom404Middleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if response.status_code == 404:
            return JsonResponse({
                'error': 'Not found',
                'status': 404,
                'message': f'The requested path {request.path} was not found',
                'path': request.path
            }, status=404)
        return response

    def process_exception(self, request, exception):
        if hasattr(exception, 'status_code') and exception.status_code == 404:
            return JsonResponse({
                'error': 'Not found',
                'status': 404,
                'message': str(exception),
                'path': request.path
            }, status=404)
        return None