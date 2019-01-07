// @flow
import * as React from 'react'
import * as Kb from '../../common-adapters'
import * as Types from '../../constants/types/tracker2'
import * as Constants from '../../constants/tracker2'
import * as Styles from '../../styles'
import {chunk} from 'lodash-es'
import Bio from '../../tracker2/bio/container'
import Assertion from '../../tracker2/assertion/container'
import Actions from './actions'
import Friend from './friend/container'
import Measure from './measure'

export type Props = {|
  assertionKeys: ?$ReadOnlyArray<string>,
  followThem: boolean,
  followers: $ReadOnlyArray<string>,
  following: $ReadOnlyArray<string>,
  backgroundColor: string,
  onFollow: () => void,
  onUnfollow: () => void,
  onBack: () => void,
  onChat: () => void,
  onClose: () => void,
  onReload: () => void,
  onIgnoreFor24Hours: () => void,
  onAccept: () => void,
  state: Types.DetailsState,
  teamShowcase: ?$ReadOnlyArray<Types._TeamShowcase>,
  username: string,
|}

const Header = ({onBack, state, backgroundColor}) => (
  <Kb.Box2
    direction="horizontal"
    fullWidth={true}
    style={Styles.collapseStyles([styles.header, {backgroundColor}])}
  >
    <Kb.BackButton iconColor={Styles.globalColors.white} textStyle={styles.backButton} onClick={onBack} />
    <Kb.Text type="Body">TODO search</Kb.Text>
  </Kb.Box2>
)

const BioLayout = p => (
  <Kb.Box2 direction="vertical" style={styles.bio}>
    <Kb.ConnectedNameWithIcon
      username={p.username}
      colorFollowing={true}
      notFollowingColorOverride={Styles.globalColors.orange}
      avatarSize={avatarSize}
    />
    <Kb.Box2 direction="vertical" fullWidth={true} gap="small">
      <Bio inTracker={false} username={p.username} />
      <Actions
        followThem={p.followThem}
        onFollow={p.onFollow}
        onUnfollow={p.onUnfollow}
        onBack={p.onBack}
        onChat={p.onChat}
        onClose={p.onClose}
        onReload={p.onReload}
        onIgnoreFor24Hours={p.onIgnoreFor24Hours}
        onAccept={p.onAccept}
        state={p.state}
      />
    </Kb.Box2>
  </Kb.Box2>
)

const TeamShowcase = ({name}) => (
  <Kb.Box2 direction="horizontal" fullWidth={true} gap="tiny" style={styles.teamShowcase}>
    <Kb.Avatar size={32} teamname={name} isTeam={true} />
    <Kb.Text type="BodySemibold">{name}</Kb.Text>
  </Kb.Box2>
)

const Teams = p =>
  p.teamShowcase && p.teamShowcase.length > 0 ? (
    <Kb.Box2 direction="vertical" gap="tiny" fullWidth={true} style={styles.teamShowcases}>
      <Kb.Text type="BodySmallSemibold">Teams</Kb.Text>
      {p.teamShowcase.map(t => (
        <TeamShowcase key={t.name} name={t.name} />
      ))}
    </Kb.Box2>
  ) : null

const Proofs = p => {
  let assertions
  if (p.assertionKeys) {
    // $ForceType readOnlyArray doens't like sort()
    assertions = p.assertionKeys
      .sort(Constants.sortAssertionKeys)
      .map(a => <Assertion key={a} username={p.username} assertionKey={a} />)
  } else {
    assertions = null
  }

  return (
    <Kb.Box2 direction="vertical" fullWidth={true}>
      {assertions}
    </Kb.Box2>
  )
}

class FriendshipTabs extends React.Component<
  Props & {onChangeFollowing: boolean => void, selectedFollowing: boolean}
> {
  _tab = following => (
    <Kb.ClickableBox
      style={Styles.collapseStyles([
        styles.followTab,
        following === this.props.selectedFollowing && styles.followTabSelected,
      ])}
    >
      <Kb.Text
        type="BodySmallSemibold"
        onClick={() => this.props.onChangeFollowing(following)}
        style={
          following === this.props.selectedFollowing ? styles.followTabTextSelected : styles.followTabText
        }
      >
        {following
          ? `Following (${this.props.following.length})`
          : `Followers (${this.props.followers.length})`}
      </Kb.Text>
    </Kb.ClickableBox>
  )

  render() {
    return (
      <Kb.Box2 direction="horizontal" style={styles.followTabContainer}>
        {this._tab(false)}
        {this._tab(true)}
      </Kb.Box2>
    )
  }
}

const widthToDimentions = width => {
  const itemsInARow = Math.floor(Math.max(1, width / (Styles.isMobile ? 105 : 120)))
  const itemWidth = Math.floor(width / itemsInARow)
  return {itemWidth, itemsInARow}
}

class FriendRow extends React.PureComponent<{|usernames: Array<string>, itemWidth: number|}> {
  render() {
    return (
      <Kb.Box2 direction="horizontal" fullWidth={true} style={styles.friendRow}>
        {this.props.usernames.map(u => (
          <Friend key={u} username={u} width={this.props.itemWidth} />
        ))}
      </Kb.Box2>
    )
  }
}

type State = {|
  selectedFollowing: boolean,
  width: number,
|}
class User extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = {selectedFollowing: !!usernameSelectedFollowing[props.username], width: 0}
  }

  _changeFollowing = following => {
    this.setState(p => {
      if (p.selectedFollowing === following) {
        return
      }
      const selectedFollowing = !p.selectedFollowing
      usernameSelectedFollowing[this.props.username] = selectedFollowing
      return {selectedFollowing}
    })
  }

  _renderSectionHeader = ({section}) => {
    if (section === this._bioTeamProofsSection) {
      return (
        <Header
          key="header"
          onBack={this.props.onBack}
          state={this.props.state}
          backgroundColor={this.props.backgroundColor}
        />
      )
    }
    return (
      <FriendshipTabs
        key="tabs"
        {...this.props}
        onChangeFollowing={this._changeFollowing}
        selectedFollowing={this.state.selectedFollowing}
      />
    )
  }

  _renderBioTeamProofs = () =>
    Styles.isMobile ? (
      <Kb.Box2 direction="vertical" fullWidth={true} style={styles.bioAndProofs}>
        <Kb.Box2
          direction="vertical"
          fullWidth={true}
          style={Styles.collapseStyles([
            styles.backgroundColor,
            {backgroundColor: this.props.backgroundColor},
          ])}
        />
        <BioLayout {...this.props} />
      </Kb.Box2>
    ) : (
      <Kb.Box2 key="bioTeam" direction="horizontal" fullWidth={true} style={styles.bioAndProofs}>
        <Kb.Box2
          direction="vertical"
          fullWidth={true}
          style={Styles.collapseStyles([
            styles.backgroundColor,
            {backgroundColor: this.props.backgroundColor},
          ])}
        />
        <BioLayout {...this.props} />
        <Kb.Box2 direction="vertical" style={styles.proofs}>
          <Teams {...this.props} />
          <Proofs {...this.props} />
        </Kb.Box2>
      </Kb.Box2>
    )

  _renderOtherUsers = ({item, section, index}) => (
    <FriendRow key={'friend' + index} usernames={item} itemWidth={section.itemWidth} />
  )

  _bioTeamProofsSection = {data: ['bioTeamProofs'], renderItem: this._renderBioTeamProofs}

  _onMeasured = width => this.setState(p => (p.width !== width ? {width} : null))
  _keyExtractor = (item, index) => index

  componentWillMount() {
    this.props.onReload()
  }
  componentDidUpdate(prevProps: Props) {
    if (this.props.username !== prevProps.username) {
      this.props.onReload()
    }
  }

  render() {
    const friends = this.state.selectedFollowing ? this.props.following : this.props.followers
    const {itemsInARow, itemWidth} = widthToDimentions(this.state.width)
    // $ForceType
    const chunks = this.state.width ? chunk(friends, itemsInARow) : []

    return (
      <Kb.Box2 direction="vertical" fullWidth={true} fullHeight={true} style={styles.container}>
        <Measure onMeasured={this._onMeasured} />
        <Kb.SafeAreaViewTop style={{backgroundColor: this.props.backgroundColor, flexGrow: 0}} />
        {!!this.state.width && (
          <Kb.SectionList
            key={this.props.username + this.state.width /* forc render on user change or width change */}
            stickySectionHeadersEnabled={true}
            renderSectionHeader={this._renderSectionHeader}
            keyExtractor={this._keyExtractor}
            sections={[
              this._bioTeamProofsSection,
              {
                data: chunks,
                itemWidth,
                renderItem: this._renderOtherUsers,
              },
            ]}
            style={Styles.collapseStyles([
              styles.sectionList,
              {
                backgroundColor: Styles.isMobile ? this.props.backgroundColor : Styles.globalColors.white,
              },
            ])}
            contentContainerStyle={styles.sectionListContentStyle}
          />
        )}
      </Kb.Box2>
    )
  }
}

// don't bother to keep this in the store
const usernameSelectedFollowing = {}

const avatarSize = 128
const headerHeight = 48

const styles = Styles.styleSheetCreate({
  backButton: {color: Styles.globalColors.white},
  backgroundColor: {
    ...Styles.globalStyles.fillAbsolute,
    bottom: undefined,
    height: avatarSize / 2,
  },
  bio: Styles.platformStyles({
    common: {alignSelf: 'flex-start'},
    isElectron: {maxWidth: 350},
    isMobile: {width: '100%'},
  }),
  bioAndProofs: Styles.platformStyles({
    common: {
      justifyContent: 'space-around',
      position: 'relative',
    },
    isMobile: {paddingBottom: Styles.globalMargins.small},
  }),
  container: {
    ...Styles.globalStyles.fillAbsolute,
  },
  followTab: Styles.platformStyles({
    common: {
      alignItems: 'center',
      borderBottomColor: 'white',
      borderBottomWidth: 2,
      justifyContent: 'center',
    },
    isElectron: {
      borderBottomStyle: 'solid',
      paddingBottom: Styles.globalMargins.tiny,
      paddingLeft: Styles.globalMargins.small,
      paddingRight: Styles.globalMargins.small,
      paddingTop: Styles.globalMargins.medium,
    },
    isMobile: {
      height: Styles.globalMargins.large,
      width: '50%',
    },
  }),
  followTabContainer: Styles.platformStyles({
    common: {
      alignItems: 'flex-end',
      backgroundColor: Styles.globalColors.white,
      borderBottomColor: Styles.globalColors.black_10,
      borderBottomWidth: 1,
    },
    isElectron: {
      alignSelf: 'flex-start',
      borderBottomStyle: 'solid',
    },
    isMobile: {
      width: '100%',
    },
  }),
  followTabSelected: {
    borderBottomColor: Styles.globalColors.blue,
  },
  followTabText: {color: Styles.globalColors.black_60},
  followTabTextSelected: {color: Styles.globalColors.black_75},
  friendRow: Styles.platformStyles({
    common: {
      marginBottom: Styles.globalMargins.xtiny,
      marginTop: Styles.globalMargins.xtiny,
      maxWidth: '100%',
      minWidth: 0,
    },
    isElectron: {justifyContent: 'flex-start'},
    isMobile: {justifyContent: 'center'},
  }),
  header: Styles.platformStyles({
    common: {
      alignItems: 'center',
      flexShrink: 0,
    },
    isElectron: {
      height: headerHeight,
      padding: Styles.globalMargins.small,
    },
    isMobile: {},
  }),
  proofs: Styles.platformStyles({
    isElectron: {
      alignSelf: 'flex-start',
      flexShrink: 0,
      marginTop: avatarSize / 2,
      width: 350,
      paddingTop: Styles.globalMargins.small,
    },
    isMobile: {width: '100%'},
  }),
  sectionList: {width: '100%'},
  sectionListContentStyle: Styles.platformStyles({
    common: {backgroundColor: Styles.globalColors.white},
    isElectron: {},
    isMobile: {minHeight: '100%'},
  }),
  teamShowcase: {alignItems: 'center'},
  teamShowcases: {
    flexShrink: 0,
    paddingBottom: Styles.globalMargins.small,
  },
})

export default User
