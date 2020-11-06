import React from 'react'
import { View } from '@instructure/ui-view'
import { Text } from '@instructure/ui-text'
import { TextInput } from '@instructure/ui-text-input'
import { TextArea } from '@instructure/ui-text-area'
import { Button } from '@instructure/ui-buttons'
import { ScreenReaderContent } from '@instructure/ui-a11y-content'
import { Alert } from '@instructure/ui-alerts'
import Api from '../../Services/Api';


export default class ImageAltIsTooLong extends React.Component {
  constructor(props) {
    super(props)

    this.state = {
      textInputValue: '',
      showSuccessAlert: false,
      showFailureAlert: false,
      characterCount:  0
    }

    this.handleButton = this.handleButton.bind(this)
    this.handleInput = this.handleInput.bind(this)
  }

  handleButton() {
    console.log(this.state.textInputValue)
    
    //Submit input value via api call

    // Alert for success
    this.setState({
      showSuccessAlert: true
    })
    
    // Alert for failure

  }

  handleInput(event){
    console.log(event.target.value)

    this.setState({
      textInputValue: event.target.value,
      characterCount: event.target.value.length
    })
  }

  renderAlert(){
    if(this.state.showSuccessAlert) {
      return <Alert
      variant="success"
      renderCloseButtonLabel="Close"
      margin="small"
      transition="none"
    >
      Your changes have been submitted
    </Alert>
    } else if(this.state.showFailureAlert) {

    }
  }

  render() {
    const UFixitApi = new Api()

    return (
        <View display="block" textAlign="start">
          <View display="block" margin="medium">
            {this.renderAlert()}
          </View>
          <View display="block" margin="medium">
            <Text weight="bold">Alternative Text</Text>
          </View>
          <View display="block" margin="medium">
          <TextArea
            renderLabel={<ScreenReaderContent>Shortened Alternative Text</ScreenReaderContent>}
            display="inline-block"
            width="25rem"
            onChange={this.handleInput}
            placeholder="Shortened alterntive text"
          />  
        </View>
        <View display="block" margin="medium">
          <Text>Current character count: {this.state.characterCount}</Text>
        </View>
        <View display="block" margin="medium"></View>
          <View display="block" margin="medium">
            <Button color="primary" onClick={this.handleButton}>Save Changes</Button>
          </View>
        </View>
    );
  }
}