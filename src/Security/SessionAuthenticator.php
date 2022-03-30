<?php

namespace App\Security;

use App\Entity\User; // your user entity
use App\Services\SessionService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class SessionAuthenticator extends AbstractAuthenticator
{
    private $em;
    private $sessionService;

    public function __construct(
        RequestStack $requestStack, 
        EntityManagerInterface $em, 
        SessionService $sessionService)
    {
        $requestStack->getCurrentRequest();
        $this->em = $em;
        $this->sessionService = $sessionService;
    }

    public function supports(Request $request): ?bool
    {
        return $this->sessionService->hasSession();
    }

    public function authenticate(Request $request): Passport
    {
        $apiToken = $request->headers->get('X-AUTH-TOKEN');
        if (null === $apiToken) {
            // The token header was empty, authentication fails with HTTP Status
            // Code 401 "Unauthorized"
            throw new CustomUserMessageAuthenticationException('No API token provided');
        }

        return new SelfValidatingPassport(new UserBadge($apiToken));
    }

    public function getCredentials(Request $request)
    {
        $session = $this->sessionService->getSession();

        return $session->get('userId');
    }

    public function checkCredentials($credentials, UserInterface $user) 
    {
        return is_numeric($credentials);
    }

    public function getUser($userId, UserProviderInterface $userProvider)
    {
        return $this->em->getRepository(User::class)->find($userId);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }

    public function start(Request $request, AuthenticationException $exception = null) 
    {
        $data = [
            // you might translate this message
            'message' => 'Session authentication failed.'
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {

    }
}
