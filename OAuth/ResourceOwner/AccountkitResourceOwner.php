<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\OAuth\ResourceOwner;

use Buzz\Message\RequestInterface as HttpRequestInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * AccountkitResourceOwner.
 *
 * @author Patrick McAndrew <patrick@so-sure.com>
 */
class AccountkitResourceOwner extends FacebookResourceOwner
{
    /**
     * {@inheritdoc}
     */
    protected $paths = array(
        'identifier' => 'id',
        'nickname' => 'name',
        'firstname' => 'first_name',
        'lastname' => 'last_name',
        'realname' => 'name',
        'email' => 'email',
    );

    /**
     * {@inheritdoc}
     */
    public function getAccessToken(Request $request, $redirectUri, array $extraParameters = array())
    {
        $parameters = array_merge(array(
            'code' => $request->query->get('code'),
            'grant_type' => 'authorization_code',
            'access_token' => sprintf("AA|%s|%s", $this->options['client_id'], $this->options['client_secret'])   
        ), $extraParameters);

        $response = $this->doGetTokenRequest($this->options['access_token_url'], $parameters);
        $response = $this->getResponseContent($response);

        $this->validateResponseContent($response);

        return $response;
    }

    /**
     * {@inheritdoc}
     */
    protected function doGetTokenRequest($url, array $parameters = array())
    {
        return $this->httpRequest(sprintf('%s?%s', $url, http_build_query($parameters, '', '&')));
    }

    /**
     * {@inheritdoc}
     */
    protected function configureOptions(OptionsResolver $resolver)
    {
        parent::configureOptions($resolver);

        $resolver->setDefaults(array(
            'authorization_url' => 'https://www.accountkit.com/v1.0/basic/dialog/sms_login',
            'access_token_url' => 'https://graph.accountkit.com/v1.2/access_token',
            'revoke_token_url' => 'https://graph.facebook.com/v2.7/me/permissions',
            'infos_url' => 'https://graph.accountkit.com/v1.2/me',
            'display' => null,
            'appsecret_proof' => false,
            'use_bearer_authorization' => true,
        ));

        // Symfony <2.6 BC
        if (method_exists($resolver, 'setDefined')) {
            $resolver
                ->setAllowedValues('display', array('page', 'popup', 'touch', null)) // @link https://developers.facebook.com/docs/reference/dialogs/#display
                ->setAllowedTypes('appsecret_proof', 'bool') // @link https://developers.facebook.com/docs/graph-api/securing-requests
            ;
        } else {
            $resolver->setAllowedValues(array(
                'display' => array('page', 'popup', 'touch', null),
                'appsecret_proof' => array(true, false),
            ));
        }
    }
}
