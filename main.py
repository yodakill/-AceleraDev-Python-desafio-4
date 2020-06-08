import jwt


def create_token(data, secret):
    """
    Cria um token com JWT (JSON Web Token)
    :param data: arquivo com dados a serem criptografados
    :param secret: chave a ser usada para decriptografar o token
    :return:retorna token encriptado
    """
    return jwt.encode(payload=data, key=secret, algorithm='HS256')


def verify_signature(token):
    """
    Decodifica o token fornecido
    :param token: sequência de caracteres criptografada contendo dados de entrada
    :return: arquivo json com dados decriptados
    """

    try:
        return jwt.decode(jwt=token, key='acelera', algorithms='HS256')

    except jwt.exceptions.InvalidSignatureError:
        data = {'error': 2}
        """
        Gerado quando a assinatura de um token não corresponde à fornecida como parte do token.
        """
    return data
