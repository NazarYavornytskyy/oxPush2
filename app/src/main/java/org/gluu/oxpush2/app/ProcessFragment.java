package org.gluu.oxpush2.app;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.google.gson.Gson;

import org.apache.commons.codec.binary.StringUtils;
import org.gluu.oxpush2.app.listener.OxPush2RequestListener;
import org.gluu.oxpush2.model.OxPush2Request;
import org.gluu.oxpush2.model.U2fMetaData;
import org.gluu.oxpush2.model.U2fOperationResult;
import org.gluu.oxpush2.net.HTTP;
import org.gluu.oxpush2.u2f.v2.exception.U2FException;
import org.gluu.oxpush2.u2f.v2.model.TokenResponse;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Process Fido U2F request fragment
 *
 * Created by Yuriy Movchan on 01/07/2016.
 */
public class ProcessFragment extends Fragment implements View.OnClickListener {

    private static final boolean DEBUG = true;
    private static final String TAG = "process-fragment";

    private static final String ARG_PARAM1 = "oxPush2Request";

    private OxPush2Request oxPush2Request;

    private OxPush2RequestListener oxPush2RequestListener;

    public ProcessFragment() {}

    /**
     * Use this factory method to create a new instance of
     * this fragment using the provided parameters.
     *
     * @return A new instance of fragment ProcessFragment.
     */
    public static ProcessFragment newInstance(String oxPush2RequestJson) {
        ProcessFragment fragment = new ProcessFragment();
        Bundle args = new Bundle();
        args.putString(ARG_PARAM1, oxPush2RequestJson);
        fragment.setArguments(args);

        return fragment;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (getArguments() != null) {
            String oxPush2RequestJson = getArguments().getString(ARG_PARAM1);

            oxPush2Request = new Gson().fromJson(oxPush2RequestJson, OxPush2Request.class);
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View view = inflater.inflate(R.layout.fragment_process, container, false);

        view.findViewById(R.id.button_approve).setOnClickListener(this);
        view.findViewById(R.id.button_decline).setOnClickListener(this);

        return view;
    }

    @Override
    public void onResume() {
        super.onResume();
    }

    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        if (context instanceof OxPush2RequestListener) {
            oxPush2RequestListener = (OxPush2RequestListener) context;
        } else {
            throw new RuntimeException(context.toString()  + " must implement OxPush2RequestListener");
        }
    }

    @Override
    public void onDetach() {
        super.onDetach();
        oxPush2RequestListener = null;
    }

    @Override
    public void onClick(View v) {
        if (oxPush2RequestListener == null) {
            return;
        }

        switch(v.getId()){
            case R.id.button_approve:
                onOxPushApproveRequest();
                break;
            case R.id.button_decline:
                onOxPushDeclineRequest();
                break;
        }
    }
    private void runOnUiThread(Runnable runnable) {
        Activity activity = getActivity();
        if (activity != null) {
            activity.runOnUiThread(runnable);
        } else {
            if (DEBUG) Log.d(TAG, "Activity is null!");
        }
    }

    private void setFinalStatus(int statusId) {
        ((TextView) getView().findViewById(R.id.status_text)).setText(statusId);
        getView().findViewById(R.id.progressBar).setVisibility(View.INVISIBLE);
    }

    private void onOxPushApproveRequest() {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                getView().findViewById(R.id.action_button_group).setVisibility(View.INVISIBLE);
                getView().findViewById(R.id.status_text).setVisibility(View.VISIBLE);
                getView().findViewById(R.id.progressBar).setVisibility(View.VISIBLE);

                ((TextView) getView().findViewById(R.id.status_text)).setText(R.string.process_u2f_start);
            }
        });

        final Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("username", oxPush2Request.getUserName());
        parameters.put("application", oxPush2Request.getApp());
        parameters.put("session_state", oxPush2Request.getState());

        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    final U2fMetaData u2fMetaData = getU2fMetaData();

                    if (DEBUG) Log.i(TAG, "Authentication method: " + oxPush2Request.getMethod());

                    final String u2fEndpoint;
                    if (StringUtils.equals(oxPush2Request.getMethod(), "enroll")) {
                        u2fEndpoint = u2fMetaData.getRegistrationEndpoint();
                    } else {
                        u2fEndpoint = u2fMetaData.getAuthenticationEndpoint();
                    }

                    final String challengeJsonResponse = HTTP.get(u2fEndpoint, parameters);
                    if (DEBUG) Log.i(TAG, "Get U2F JSON response: " + challengeJsonResponse);

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                onChallengeReceived(u2fMetaData, u2fEndpoint, challengeJsonResponse);
                            } catch (Exception ex) {
                                Log.e(TAG, "Failed to process challengeJsonResponse: " + challengeJsonResponse, ex);
                                setFinalStatus(R.string.failed_process_challenge);
                            }
                        }
                    });
                } catch (Exception ex) {
                    Log.e(TAG, "Failed to get Fido U2F metadata", ex);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setFinalStatus(R.string.wrong_u2f_metadata);
                        }
                    });
                }
            }
        }).start();
    }

    private void onOxPushDeclineRequest() {

    }

    private U2fMetaData getU2fMetaData() throws IOException {
        // Request U2f meta data
        String discoveryUrl = oxPush2Request.getIssuer();
        if (DEBUG && discoveryUrl.contains(":8443")) {
            discoveryUrl += "/oxauth/seam/resource/restv1/oxauth/fido-u2f-configuration";
        } else {
            discoveryUrl += "/.well-known/fido-u2f-configuration";
        }

        if (DEBUG) Log.i(TAG, "Attempting to load U2F metadata from: " + discoveryUrl);

        final String discoveryJson = HTTP.get(discoveryUrl, null);
        final U2fMetaData u2fMetaData = new Gson().fromJson(discoveryJson, U2fMetaData.class);

        if (DEBUG) Log.i(TAG, "Loaded U2f metadata: " + u2fMetaData);

        return u2fMetaData;
    }

    private void onChallengeReceived(final U2fMetaData u2fMetaData, final String u2fEndpoint, final String challengeJson) throws IOException, JSONException, U2FException {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                ((TextView) getView().findViewById(R.id.status_text)).setText(R.string.process_u2f_request);
            }
        });

        final boolean enroll = StringUtils.equals(oxPush2Request.getMethod(), "enroll");
        final TokenResponse tokenResponse;
        if (enroll) {
            tokenResponse = oxPush2RequestListener.onEnroll(challengeJson, oxPush2Request.getIssuer());
        } else {
            tokenResponse = oxPush2RequestListener.onSign(challengeJson, u2fMetaData.getIssuer());
        }

        if (tokenResponse == null) {
            if (DEBUG) Log.e(TAG, "Token response is empty");
            setFinalStatus(R.string.wrong_token_response);
            return;
        }

        final Map<String, String> parameters = new HashMap<String, String>();
        parameters.put("username", oxPush2Request.getUserName());
        parameters.put("tokenResponse", tokenResponse.getResponse());
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    final String resultJsonResponse = HTTP.post(u2fEndpoint, parameters);
                    if (DEBUG) Log.i(TAG, "Get U2F JSON result response: " + resultJsonResponse);

                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            try {
                                final U2fOperationResult u2fOperationResult = new Gson().fromJson(resultJsonResponse, U2fOperationResult.class);
                                if (DEBUG) Log.i(TAG, "Get U2f operation result: " + u2fOperationResult);

                                handleResult(u2fMetaData, tokenResponse, u2fOperationResult);
                            } catch (Exception ex) {
                                Log.e(TAG, "Failed to process resultJsonResponse: " + resultJsonResponse, ex);
                                setFinalStatus(R.string.failed_process_status);
                            }
                        }
                    });
                } catch (Exception ex) {
                    Log.e(TAG, "Failed to send Fido U2F response", ex);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            setFinalStatus(R.string.failed_process_response);
                        }
                    });
                }
            }
        }).start();
    }

    private void handleResult(U2fMetaData u2fMetaData, TokenResponse tokenResponse, U2fOperationResult u2fOperationResult) {
        if (!StringUtils.equals(tokenResponse.getChallenge(), u2fOperationResult.getChallenge())) {
            setFinalStatus(R.string.challenge_doesnt_match);
        }

        if (StringUtils.equals("success", u2fOperationResult.getStatus())) {
            setFinalStatus(R.string.auth_result_success);

            ((TextView) getView().findViewById(R.id.status_text)).setText(getString(R.string.auth_result_success) + ". Server: " + u2fMetaData.getIssuer());
        } else {
            setFinalStatus(R.string.auth_result_failed);
        }
    }

}
